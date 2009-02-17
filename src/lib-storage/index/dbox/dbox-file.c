/* Copyright (c) 2007-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "hex-dec.h"
#include "hostpid.h"
#include "istream.h"
#include "ostream.h"
#include "mkdir-parents.h"
#include "fdatasync-path.h"
#include "str.h"
#include "maildir/maildir-uidlist.h"
#include "dbox-storage.h"
#include "dbox-file.h"
#include "dbox-file-maildir.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

enum mail_flags dbox_mail_flags_map[DBOX_METADATA_FLAGS_COUNT] = {
	MAIL_ANSWERED,
	MAIL_FLAGGED,
	MAIL_DELETED,
	MAIL_SEEN,
	MAIL_DRAFT
};

char dbox_mail_flag_chars[DBOX_METADATA_FLAGS_COUNT] = {
	'A', 'F', 'D', 'S', 'T'
};

static int dbox_file_metadata_skip_header(struct dbox_file *file);

static char *dbox_generate_tmp_filename(void)
{
	static unsigned int create_count = 0;

	return i_strdup_printf("temp.%lu.P%sQ%uM%u.%s",
			       (unsigned long)ioloop_timeval.tv_sec, my_pid,
			       create_count++,
			       (unsigned int)ioloop_timeval.tv_usec,
			       my_hostname);
}

void dbox_file_set_syscall_error(struct dbox_file *file, const char *function)
{
	mail_storage_set_critical(&file->storage->storage,
				  "%s(%s) failed: %m", function,
				  dbox_file_get_path(file));
}

static void
dbox_file_set_corrupted(struct dbox_file *file, const char *reason)
{
	mail_storage_set_critical(&file->storage->storage,
				  "%s corrupted: %s", dbox_file_get_path(file),
				  reason);
}


static struct dbox_file *
dbox_find_and_move_open_file(struct dbox_storage *storage, uint32_t file_id)
{
	struct dbox_file *const *files, *file;
	unsigned int i, count;

	files = array_get(&storage->open_files, &count);
	for (i = 0; i < count; i++) {
		if (files[i]->file_id == file_id) {
			/* move to last in the array */
			file = files[i];
			array_delete(&storage->open_files, i, 1);
			array_append(&storage->open_files, &file, 1);
			return file;
		}
	}
	return NULL;
}

static void dbox_file_free(struct dbox_file *file)
{
	i_assert(file->refcount == 0);

	if (file->metadata_pool != NULL)
		pool_unref(&file->metadata_pool);
	dbox_file_close(file);
	i_free(file->current_path);
	i_free(file->fname);
	i_free(file);
}

void dbox_files_free(struct dbox_storage *storage)
{
	struct dbox_file *const *files;
	unsigned int i, count;

	files = array_get(&storage->open_files, &count);
	for (i = 0; i < count; i++)
		dbox_file_free(files[i]);
	array_clear(&storage->open_files);
}

static void
dbox_close_open_files(struct dbox_storage *storage, unsigned int close_count)
{
	struct dbox_file *const *files;
	unsigned int i, count;

	files = array_get(&storage->open_files, &count);
	for (i = 0; i < count;) {
		if (files[i]->refcount == 0) {
			dbox_file_free(files[i]);
			array_delete(&storage->open_files, i, 1);

			if (--close_count == 0)
				break;

			files = array_get(&storage->open_files, &count);
		} else {
			i++;
		}
	}
}

static bool
dbox_maildir_uid_get_fname(struct dbox_mailbox *mbox, uint32_t uid,
			   const char **fname_r)
{
	enum maildir_uidlist_rec_flag flags;

	*fname_r = maildir_uidlist_lookup(mbox->maildir_uidlist, uid, &flags);
	return *fname_r != NULL;
}

static char *
dbox_file_uid_get_fname(struct dbox_mailbox *mbox, uint32_t uid,
			bool *maildir_file_r)
{
	const char *fname;

	if (uid <= mbox->highest_maildir_uid &&
	    dbox_maildir_uid_get_fname(mbox, uid, &fname)) {
		*maildir_file_r = TRUE;
		return i_strdup(fname);
	} else {
		*maildir_file_r = FALSE;
		return i_strdup_printf(DBOX_MAIL_FILE_UID_FORMAT, uid);
	}
}

const char *dbox_file_get_primary_path(struct dbox_file *file)
{
	const char *dir;

	dir = file->single_mbox != NULL ? file->single_mbox->path :
		file->storage->storage_dir;
	return t_strdup_printf("%s/%s", dir, file->fname);
}

const char *dbox_file_get_alt_path(struct dbox_file *file)
{
	const char *dir;

	dir = file->single_mbox != NULL ? file->single_mbox->alt_path :
		file->storage->alt_storage_dir;
	return t_strdup_printf("%s/%s", dir, file->fname);
}

struct dbox_file *
dbox_file_init_single(struct dbox_mailbox *mbox, uint32_t uid)
{
	struct dbox_file *file;
	bool maildir;

	file = i_new(struct dbox_file, 1);
	file->refcount = 1;
	file->storage = mbox->storage;
	file->single_mbox = mbox;
	file->fd = -1;
	if (uid != 0) {
		file->uid = uid;
		file->fname = dbox_file_uid_get_fname(mbox, uid, &maildir);
		file->maildir_file = maildir;
	} else {
		file->fname = dbox_generate_tmp_filename();
	}
	file->current_path = i_strdup_printf("%s/%s", mbox->path, file->fname);
	return file;
}

struct dbox_file *
dbox_file_init_multi(struct dbox_storage *storage, uint32_t file_id)
{
	struct dbox_file *file;
	unsigned int count;

	file = file_id == 0 ? NULL :
		dbox_find_and_move_open_file(storage, file_id);
	if (file != NULL) {
		file->refcount++;
		return file;
	}

	count = array_count(&storage->open_files);
	if (count > storage->max_open_files)
		dbox_close_open_files(storage, count - storage->max_open_files);

	file = i_new(struct dbox_file, 1);
	file->refcount = 1;
	file->storage = storage;
	file->fd = -1;
	file->fname = file_id == 0 ? dbox_generate_tmp_filename() :
		i_strdup_printf(DBOX_MAIL_FILE_MULTI_FORMAT, file_id);
	file->current_path =
		i_strdup_printf("%s/%s", storage->storage_dir, file->fname);

	if (file_id != 0)
		array_append(&storage->open_files, &file, 1);
	return file;
}

int dbox_file_assign_id(struct dbox_file *file, uint32_t id)
{
	const char *old_path;
	char *new_fname, *new_path;
	bool maildir;

	i_assert(!file->maildir_file);
	i_assert(file->uid == 0 && file->file_id == 0);
	i_assert(id != 0);

	old_path = dbox_file_get_path(file);
	if (file->single_mbox != NULL) {
		new_fname = dbox_file_uid_get_fname(file->single_mbox,
						    id, &maildir);
		new_path = i_strdup_printf("%s/%s", file->single_mbox->path,
					   new_fname);
	} else {
		new_fname = i_strdup_printf(DBOX_MAIL_FILE_MULTI_FORMAT, id);
		new_path = i_strdup_printf("%s/%s", file->storage->storage_dir,
					   new_fname);
	}
	if (rename(old_path, new_path) < 0) {
		mail_storage_set_critical(&file->storage->storage,
					  "rename(%s, %s) failed: %m",
					  old_path, new_path);
		i_free(new_fname);
		i_free(new_path);
		return -1;
	}
	i_free(file->fname);
	i_free(file->current_path);
	file->fname = new_fname;
	file->current_path = new_path;

	if (file->single_mbox != NULL)
		file->uid = id;
	else {
		file->file_id = id;
		array_append(&file->storage->open_files, &file, 1);
	}
	return 0;
}

void dbox_file_unref(struct dbox_file **_file)
{
	struct dbox_file *file = *_file;
	struct dbox_file *const *files;
	unsigned int i, count;

	*_file = NULL;

	i_assert(file->refcount > 0);
	if (--file->refcount > 0)
		return;

	/* don't cache metadata seeks while file isn't being referenced */
	file->metadata_read_offset = 0;

	if (file->file_id != 0) {
		files = array_get(&file->storage->open_files, &count);
		if (!file->deleted && count <= file->storage->max_open_files) {
			/* we can leave this file open for now */
			return;
		}

		for (i = 0; i < count; i++) {
			if (files[i] == file)
				break;
		}
		i_assert(i != count);
		array_delete(&file->storage->open_files, i, 1);
	}

	dbox_file_free(file);
}

static time_t day_begin_stamp(unsigned int days)
{
	struct tm tm;
	time_t stamp;

	if (days == 0)
		return 0;

	/* get beginning of today */
	tm = *localtime(&ioloop_time);
	tm.tm_hour = 0;
	tm.tm_min = 0;
	tm.tm_sec = 0;
	stamp = mktime(&tm);
	if (stamp == (time_t)-1)
		i_panic("mktime(today) failed");

	return stamp - (3600*24 * (days-1));
}

bool dbox_file_can_append(struct dbox_file *file, uoff_t mail_size)
{
	if (file->nonappendable)
		return FALSE;

	if (file->append_offset == 0) {
		/* messages have been expunged */
		return FALSE;
	}

	if (file->append_offset < file->storage->rotate_min_size ||
	    file->append_offset == file->file_header_size)
		return TRUE;
	if (file->append_offset + mail_size >= file->storage->rotate_size)
		return FALSE;
	return file->create_time >= day_begin_stamp(file->storage->rotate_days);
}

static int dbox_file_parse_header(struct dbox_file *file, const char *line)
{
	const char *const *tmp, *value;
	unsigned int pos, version;
	enum dbox_header_key key;

	version = *line - '0';
	if (line[1] != ' ' || (version != 1 && version != DBOX_VERSION)) {
		dbox_file_set_corrupted(file, "Invalid dbox version");
		return -1;
	}
	line += 2;
	pos = 2;

	file->msg_header_size = 0;

	for (tmp = t_strsplit(line, " "); *tmp != NULL; tmp++) {
		key = **tmp;
		value = *tmp + 1;

		switch (key) {
		case DBOX_HEADER_OLDV1_APPEND_OFFSET:
			break;
		case DBOX_HEADER_MSG_HEADER_SIZE:
			file->msg_header_size = strtoul(value, NULL, 16);
			break;
		case DBOX_HEADER_CREATE_STAMP:
			file->create_time = strtoul(value, NULL, 16);
			break;
		}
		pos += strlen(value) + 2;
	}

	if (file->msg_header_size == 0) {
		dbox_file_set_corrupted(file, "Missing message header size");
		return -1;
	}

	if (!file->nonappendable)
		file->nonappendable = !dbox_file_can_append(file, 0);
	return 0;
}

static int dbox_file_read_header(struct dbox_file *file)
{
	const char *line;
	int ret;

	i_stream_seek(file->input, 0);
	line = i_stream_read_next_line(file->input);
	if (line == NULL) {
		if (file->input->stream_errno == 0)
			return 0;

		dbox_file_set_syscall_error(file, "read");
		return -1;
	}
	file->file_header_size = file->input->v_offset;
	T_BEGIN {
		ret = dbox_file_parse_header(file, line) < 0 ? 0 : 1;
	} T_END;
	return ret;
}

static int dbox_file_open_fd(struct dbox_file *file)
{
	const char *path;
	bool alt = FALSE;

	/* try the primary path first */
	path = dbox_file_get_primary_path(file);
	while ((file->fd = open(path, O_RDWR)) == -1) {
		if (errno != ENOENT) {
			mail_storage_set_critical(&file->storage->storage,
						  "open(%s) failed: %m", path);
			return -1;
		}

		if (file->storage->alt_storage_dir == NULL || alt) {
			/* not found */
			return 0;
		}

		/* try the alternative path */
		path = dbox_file_get_alt_path(file);
		alt = TRUE;
	}
	i_free(file->current_path);
	file->current_path = i_strdup(path);
	file->alt_path = alt;
	return 1;
}

static int dbox_file_open(struct dbox_file *file, bool read_header,
			  bool *deleted_r)
{
	int ret;

	i_assert(file->input == NULL);

	*deleted_r = FALSE;

	if (file->fd == -1) {
		T_BEGIN {
			ret = dbox_file_open_fd(file);
		} T_END;
		if (ret <= 0) {
			if (ret < 0)
				return -1;
			*deleted_r = TRUE;
			return 1;
		}
	}

	file->input = i_stream_create_fd(file->fd, MAIL_READ_BLOCK_SIZE, FALSE);
	return !read_header || file->maildir_file ? 1 :
		dbox_file_read_header(file);
}

static int dbox_create_fd(struct dbox_storage *storage, const char *path)
{
	mode_t old_mask;
	int fd;

	old_mask = umask(0777 & ~storage->create_mode);
	fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0777);
	umask(old_mask);
	if (fd == -1) {
		mail_storage_set_critical(&storage->storage,
			"open(%s, O_CREAT) failed: %m", path);
	} else if (storage->create_gid != (gid_t)-1) {
		if (fchown(fd, (uid_t)-1, storage->create_gid) < 0) {
			mail_storage_set_critical(&storage->storage,
				"fchown(%s, -1, %ld) failed: %m",
				path, (long)storage->create_gid);
			/* continue anyway */
		}
	}
	return fd;
}

static int dbox_file_create(struct dbox_file *file)
{
	string_t *hdr;

	i_assert(file->fd == -1);

	file->fd = dbox_create_fd(file->storage, file->current_path);
	if (file->fd == -1)
		return -1;
	file->output = o_stream_create_fd_file(file->fd, 0, FALSE);

	hdr = t_str_new(128);
	str_printfa(hdr, "%u %c%x %c%x\n", DBOX_VERSION,
		    DBOX_HEADER_MSG_HEADER_SIZE,
		    (unsigned int)sizeof(struct dbox_message_header),
		    DBOX_HEADER_CREATE_STAMP, (unsigned int)ioloop_time);

	file->file_header_size = str_len(hdr);
	file->msg_header_size = sizeof(struct dbox_message_header);
	file->append_offset = str_len(hdr);

	if (o_stream_send(file->output, str_data(hdr), str_len(hdr)) < 0) {
		dbox_file_set_syscall_error(file, "write");
		return -1;
	}
	return 0;
}

int dbox_file_open_or_create(struct dbox_file *file, bool read_header,
			     bool *deleted_r)
{
	int ret;

	*deleted_r = FALSE;

	if (file->file_id == 0 && file->uid == 0) {
		T_BEGIN {
			ret = dbox_file_create(file) < 0 ? -1 : 1;
		} T_END;
		return ret;
	} else if (file->input != NULL)
		return 1;
	else
		return dbox_file_open(file, read_header, deleted_r);
}

int dbox_file_open_if_needed(struct dbox_file *file)
{
	const char *path;
	int ret;

	if (file->fd != -1)
		return 0;

	T_BEGIN {
		ret = dbox_file_open_fd(file);
	} T_END;
	if (ret == 0) {
		path = dbox_file_get_primary_path(file);
		mail_storage_set_critical(&file->storage->storage,
					  "open(%s) failed: %m", path);
	}
	return ret <= 0 ? -1 : 0;
}

void dbox_file_close(struct dbox_file *file)
{
	if (file->input != NULL)
		i_stream_unref(&file->input);
	if (file->output != NULL)
		o_stream_unref(&file->output);
	if (file->fd != -1) {
		if (close(file->fd) < 0)
			dbox_file_set_syscall_error(file, "close");
		file->fd = -1;
	}
}

const char *dbox_file_get_path(struct dbox_file *file)
{
	return file->current_path;
}

static int
dbox_file_get_maildir_data(struct dbox_file *file, uoff_t *physical_size_r)
{
	struct stat st;

	i_assert(file->uid != 0);

	if (fstat(file->fd, &st) < 0) {
		dbox_file_set_syscall_error(file, "fstat");
		return -1;
	}

	*physical_size_r = st.st_size;
	return 1;
}

static int
dbox_file_read_mail_header(struct dbox_file *file, uoff_t *physical_size_r)
{
	struct dbox_message_header hdr;
	const unsigned char *data;
	size_t size;
	int ret;

	if (file->maildir_file)
		return dbox_file_get_maildir_data(file, physical_size_r);

	ret = i_stream_read_data(file->input, &data, &size,
				 file->msg_header_size - 1);
	if (ret <= 0) {
		if (file->input->stream_errno == 0) {
			/* EOF, broken offset */
			return 0;
		}
		dbox_file_set_syscall_error(file, "read");
		return -1;
	}
	if (data[file->msg_header_size-1] != '\n')
		return 0;

	memcpy(&hdr, data, I_MIN(sizeof(hdr), file->msg_header_size));
	if (memcmp(hdr.magic_pre, DBOX_MAGIC_PRE, sizeof(hdr.magic_pre)) != 0) {
		/* probably broken offset */
		return 0;
	}

	*physical_size_r = hex2dec(hdr.message_size_hex,
				   sizeof(hdr.message_size_hex));
	return 1;
}

int dbox_file_get_mail_stream(struct dbox_file *file, uoff_t offset,
			      uoff_t *physical_size_r,
			      struct istream **stream_r, bool *expunged_r)
{
	int ret;

	*expunged_r = FALSE;

	if (file->input == NULL) {
		if ((ret = dbox_file_open(file, TRUE, expunged_r)) <= 0 ||
		    *expunged_r)
			return ret;
	}

	if (offset == 0)
		offset = file->file_header_size;

	if (offset != file->cur_offset || file->cur_physical_size == 0) {
		file->cur_offset = offset;
		i_stream_seek(file->input, offset);
		ret = dbox_file_read_mail_header(file, &file->cur_physical_size);
		if (ret <= 0)
			return ret;
	}
	if (stream_r != NULL) {
		i_stream_seek(file->input, offset + file->msg_header_size);
		*stream_r = i_stream_create_limit(file->input,
						  file->cur_physical_size);
	}
	*physical_size_r = file->cur_physical_size;
	return 1;
}

static int
dbox_file_seek_next_at_metadata(struct dbox_file *file, uoff_t *offset,
				uoff_t *physical_size_r)
{
	const char *line;
	int ret;

	if ((ret = dbox_file_metadata_skip_header(file)) <= 0)
		return ret;

	/* skip over the actual metadata */
	while ((line = i_stream_read_next_line(file->input)) != NULL) {
		if (*line == DBOX_METADATA_SPACE) {
			/* end of metadata */
			break;
		}
	}
	*offset = file->input->v_offset;

	(void)i_stream_read(file->input);
	if (!i_stream_have_bytes_left(file->input)) {
		*physical_size_r = 0;
		return 1;
	}

	return dbox_file_read_mail_header(file, physical_size_r);
}

int dbox_file_seek_next(struct dbox_file *file, uoff_t *offset,
			uoff_t *physical_size_r)
{
	uoff_t size;
	bool first = *offset == 0;
	bool deleted;
	int ret;

	ret = dbox_file_get_mail_stream(file, *offset, &size, NULL,
					&deleted);
	if (ret <= 0)
		return ret;

	if (deleted) {
		*physical_size_r = 0;
		return 1;
	}
	if (first) {
		*physical_size_r = size;
		return 1;
	}

	i_stream_skip(file->input, size);
	return dbox_file_seek_next_at_metadata(file, offset, physical_size_r);
}

static int dbox_file_seek_append_pos(struct dbox_file *file, uoff_t mail_size)
{
	int ret;

	if ((ret = dbox_file_read_header(file)) <= 0)
		return ret;

	if (file->append_offset == 0 ||
	    file->msg_header_size != sizeof(struct dbox_message_header) ||
	    !dbox_file_can_append(file, mail_size)) {
		/* can't append */
		return 0;
	}

	file->output = o_stream_create_fd_file(file->fd, (uoff_t)-2, FALSE);
	o_stream_seek(file->output, file->append_offset);
	return 1;
}

static int
dbox_file_get_append_stream_int(struct dbox_file *file, uoff_t mail_size,
				struct ostream **stream_r)
{
	bool deleted;
	int ret;

	if (file->fd == -1) {
		i_assert(file->output == NULL);
		if ((ret = dbox_file_open_or_create(file, FALSE,
						    &deleted)) <= 0 || deleted)
			return ret;
	}

	if (file->output == NULL) {
		ret = dbox_file_seek_append_pos(file, mail_size);
		if (ret <= 0)
			return ret;
	} else {
		if (!dbox_file_can_append(file, mail_size))
			return 0;
	}

	if (file->output->offset > (uint32_t)-1) {
		/* we use 32bit offsets to messages */
		return 0;
	}

	o_stream_ref(file->output);
	*stream_r = file->output;
	return 1;
}

int dbox_file_get_append_stream(struct dbox_file *file, uoff_t mail_size,
				struct ostream **stream_r)
{
	int ret;

	if (file->append_count == 0) {
		if (file->nonappendable)
			return 0;
	} else {
		if (!dbox_file_can_append(file, mail_size))
			return 0;
	}

	ret = dbox_file_get_append_stream_int(file, mail_size, stream_r);
	if (ret == 0)
		file->nonappendable = TRUE;
	return ret;
}

uoff_t dbox_file_get_next_append_offset(struct dbox_file *file)
{
	i_assert(file->output_stream_offset != 0);
	i_assert(file->output == NULL ||
		 file->output_stream_offset == file->output->offset);

	return file->output_stream_offset;
}

void dbox_file_cancel_append(struct dbox_file *file, uoff_t append_offset)
{
	if (ftruncate(file->fd, append_offset) < 0) {
		dbox_file_set_syscall_error(file, "ftruncate");
		file->append_offset = 0;
		file->nonappendable = TRUE;
	}

	o_stream_seek(file->output, append_offset);
	file->output_stream_offset = append_offset;
}

void dbox_file_finish_append(struct dbox_file *file)
{
	file->output_stream_offset = file->output->offset;
	file->append_offset = file->output->offset;
	file->append_count++;
}

static uoff_t
dbox_file_get_metadata_offset(struct dbox_file *file, uoff_t offset,
			      uoff_t physical_size)
{
	if (offset == 0) {
		if (file->maildir_file)
			return 0;

		i_assert(file->file_header_size != 0);
		offset = file->file_header_size;
	}
	return offset + sizeof(struct dbox_message_header) + physical_size;
}

static int dbox_file_metadata_skip_header(struct dbox_file *file)
{
	struct dbox_metadata_header metadata_hdr;
	const unsigned char *data;
	size_t size;
	int ret;

	ret = i_stream_read_data(file->input, &data, &size,
				 sizeof(metadata_hdr) - 1);
	if (ret <= 0) {
		if (file->input->stream_errno == 0) {
			/* EOF, broken offset */
			return 0;
		}
		dbox_file_set_syscall_error(file, "read");
		return -1;
	}
	memcpy(&metadata_hdr, data, sizeof(metadata_hdr));
	if (memcmp(metadata_hdr.magic_post, DBOX_MAGIC_POST,
		   sizeof(metadata_hdr.magic_post)) != 0) {
		/* probably broken offset */
		return 0;
	}
	i_stream_skip(file->input, sizeof(metadata_hdr));
	return 1;
}

int dbox_file_metadata_seek(struct dbox_file *file, uoff_t metadata_offset,
			    bool *expunged_r)
{
	const char *line;
	uoff_t metadata_data_offset, prev_offset;
	bool deleted;
	int ret;

	*expunged_r = FALSE;

	if (file->metadata_pool != NULL)
		p_clear(file->metadata_pool);
	else {
		file->metadata_pool =
			pool_alloconly_create("dbox metadata", 1024);
	}
	file->metadata_read_offset = 0;
	p_array_init(&file->metadata, file->metadata_pool, 16);

	if (file->metadata_read_offset == metadata_offset)
		return 1;
	i_assert(!file->maildir_file); /* previous check should catch this */

	if (file->input == NULL) {
		if ((ret = dbox_file_open(file, TRUE, &deleted)) <= 0)
			return ret;
		if (deleted) {
			*expunged_r = TRUE;
			return 1;
		}
	} else {
		/* make sure to flush any cached data */
		i_stream_sync(file->input);
	}

	i_stream_seek(file->input, metadata_offset);
	if ((ret = dbox_file_metadata_skip_header(file)) <= 0)
		return ret;
	metadata_data_offset = file->input->v_offset;

	*expunged_r = TRUE;
	for (;;) {
		prev_offset = file->input->v_offset;
		if ((line = i_stream_read_next_line(file->input)) == NULL)
			break;

		if (*line == DBOX_METADATA_SPACE || *line == '\0') {
			/* end of metadata */
			*expunged_r = FALSE;
			break;
		}
		line = p_strdup(file->metadata_pool, line);
		array_append(&file->metadata, &line, 1);
	}
	file->metadata_read_offset = metadata_offset;
	return 1;
}

int dbox_file_metadata_seek_mail_offset(struct dbox_file *file, uoff_t offset,
					bool *expunged_r)
{
	uoff_t physical_size, metadata_offset;
	int ret;

	ret = dbox_file_get_mail_stream(file, offset, &physical_size,
					NULL, expunged_r);
	if (ret <= 0 || *expunged_r)
		return ret;

	metadata_offset =
		dbox_file_get_metadata_offset(file, offset, physical_size);
	return dbox_file_metadata_seek(file, metadata_offset, expunged_r);
}

const char *dbox_file_metadata_get(struct dbox_file *file,
				   enum dbox_metadata_key key)
{
	const char *const *metadata;
	unsigned int i, count;

	if (file->maildir_file)
		return dbox_file_maildir_metadata_get(file, key);

	metadata = array_get(&file->metadata, &count);
	for (i = 0; i < count; i++) {
		if (*metadata[i] == (char)key)
			return metadata[i] + 1;
	}
	return NULL;
}

int dbox_file_metadata_write_to(struct dbox_file *file, struct ostream *output)
{
	struct dbox_metadata_header metadata_hdr;
	const char *const *metadata;
	unsigned int i, count;

	memset(&metadata_hdr, 0, sizeof(metadata_hdr));
	memcpy(metadata_hdr.magic_post, DBOX_MAGIC_POST,
	       sizeof(metadata_hdr.magic_post));
	if (o_stream_send(output, &metadata_hdr, sizeof(metadata_hdr)) < 0)
		return -1;

	metadata = array_get(&file->metadata, &count);
	for (i = 0; i < count; i++) {
		if (o_stream_send_str(output, metadata[i]) < 0 ||
		    o_stream_send(output, "\n", 1) < 0)
			return -1;
	}

	if (o_stream_send(output, "\n", 1) < 0)
		return -1;
	return 0;
}

int dbox_file_move(struct dbox_file *file, bool alt_path)
{
	struct ostream *output;
	const char *dest_dir, *temp_path, *dest_path;
	struct stat st;
	bool deleted;
	int out_fd, ret = 0;

	i_assert(file->input != NULL);

	if (file->alt_path == alt_path)
		return 0;

	if (stat(file->current_path, &st) < 0 && errno == ENOENT) {
		/* already expunged by another session */
		return 0;
	}

	dest_dir = !alt_path ? dbox_file_get_primary_path(file) :
		dbox_file_get_alt_path(file);
	temp_path = t_strdup_printf("%s/%s", dest_dir,
				    dbox_generate_tmp_filename());

	/* first copy the file. make sure to catch every possible error
	   since we really don't want to break the file. */
	out_fd = open(temp_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (out_fd == -1 && errno == ENOENT) {
		if (mkdir_parents(dest_dir, 0700) < 0 && errno != EEXIST) {
			i_error("mkdir_parents(%s) failed: %m", dest_dir);
			return -1;
		}
		out_fd = open(temp_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	}
	if (out_fd == -1) {
		i_error("open(%s, O_CREAT) failed: %m", temp_path);
		return -1;
	}
	output = o_stream_create_fd_file(out_fd, 0, FALSE);
	i_stream_seek(file->input, 0);
	while ((ret = o_stream_send_istream(output, file->input)) > 0) ;
	if (ret == 0)
		ret = o_stream_flush(output);
	if (output->stream_errno != 0) {
		errno = output->stream_errno;
		i_error("write(%s) failed: %m", temp_path);
		ret = -1;
	} else if (file->input->stream_errno != 0) {
		errno = file->input->stream_errno;
		i_error("read(%s) failed: %m", file->current_path);
		ret = -1;
	} else if (ret < 0) {
		i_error("o_stream_send_istream(%s, %s) "
			"failed with unknown error",
			temp_path, file->current_path);
	}
	o_stream_unref(&output);

	if ((file->storage->storage.flags &
	     MAIL_STORAGE_FLAG_FSYNC_DISABLE) == 0 && ret == 0) {
		if (fsync(out_fd) < 0) {
			i_error("fsync(%s) failed: %m", temp_path);
			ret = -1;
		}
	}
	if (close(out_fd) < 0) {
		i_error("close(%s) failed: %m", temp_path);
		ret = -1;
	}
	if (ret < 0) {
		(void)unlink(temp_path);
		return -1;
	}

	/* the temp file was successfully written. rename it now to the
	   destination file. the destination shouldn't exist, but if it does
	   its contents should be the same (except for maybe older metadata) */
	dest_path = t_strdup_printf("%s/%s", dest_dir, file->fname);
	if (rename(temp_path, dest_path) < 0) {
		i_error("rename(%s, %s) failed: %m", temp_path, dest_path);
		(void)unlink(temp_path);
		return -1;
	}
	if ((file->storage->storage.flags &
	     MAIL_STORAGE_FLAG_FSYNC_DISABLE) == 0) {
		if (fdatasync_path(dest_dir) < 0) {
			i_error("fdatasync(%s) failed: %m", dest_dir);
			(void)unlink(dest_path);
			return -1;
		}
	}
	if (unlink(file->current_path) < 0) {
		i_error("unlink(%s) failed: %m", file->current_path);
		if (errno == EACCES) {
			/* configuration problem? revert the write */
			(void)unlink(dest_path);
		}
		/* who knows what happened to the file. keep both just to be
		   sure both won't get deleted. */
		return -1;
	}

	/* file was successfully moved - reopen it */
	dbox_file_close(file);
	if (dbox_file_open(file, TRUE, &deleted) <= 0) {
		i_error("dbox_file_move(%s): reopening file failed", dest_path);
		return -1;
	}
	return 0;
}

void dbox_msg_header_fill(struct dbox_message_header *dbox_msg_hdr,
			  uoff_t message_size)
{
	memset(dbox_msg_hdr, ' ', sizeof(*dbox_msg_hdr));
	memcpy(dbox_msg_hdr->magic_pre, DBOX_MAGIC_PRE,
	       sizeof(dbox_msg_hdr->magic_pre));
	dbox_msg_hdr->type = DBOX_MESSAGE_TYPE_NORMAL;
	dec2hex(dbox_msg_hdr->message_size_hex, message_size,
		sizeof(dbox_msg_hdr->message_size_hex));
	dbox_msg_hdr->save_lf = '\n';
}
