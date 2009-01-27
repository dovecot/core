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
#include "write-full.h"
#include "str.h"
#include "dbox-storage.h"
#include "dbox-index.h"
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
	mail_storage_set_critical(file->mbox->ibox.box.storage,
				  "%s(%s) failed: %m", function,
				  dbox_file_get_path(file));
}

static void
dbox_file_set_corrupted(struct dbox_file *file, const char *reason)
{
	mail_storage_set_critical(file->mbox->ibox.box.storage,
				  "%s corrupted: %s", dbox_file_get_path(file),
				  reason);
}


static struct dbox_file *
dbox_find_and_move_open_file(struct dbox_mailbox *mbox, unsigned int file_id)
{
	struct dbox_file *const *files, *file;
	unsigned int i, count;

	files = array_get(&mbox->open_files, &count);
	for (i = 0; i < count; i++) {
		if (files[i]->file_id == file_id) {
			/* move to last in the array */
			file = files[i];
			array_delete(&mbox->open_files, i, 1);
			array_append(&mbox->open_files, &file, 1);
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

void dbox_files_free(struct dbox_mailbox *mbox)
{
	struct dbox_file *const *files;
	unsigned int i, count;

	files = array_get(&mbox->open_files, &count);
	for (i = 0; i < count; i++)
		dbox_file_free(files[i]);
	array_clear(&mbox->open_files);
}

static void
dbox_close_open_files(struct dbox_mailbox *mbox, unsigned int close_count)
{
	struct dbox_file *const *files;
	unsigned int i, count;

	files = array_get(&mbox->open_files, &count);
	for (i = 0; i < count;) {
		if (files[i]->refcount == 0) {
			dbox_file_free(files[i]);
			array_delete(&mbox->open_files, i, 1);

			if (--close_count == 0)
				break;

			files = array_get(&mbox->open_files, &count);
		} else {
			i++;
		}
	}
}

static char *
dbox_file_id_get_fname(struct dbox_mailbox *mbox, unsigned int file_id,
		       bool *maildir_file_r)
{
	struct dbox_index_record *rec;
	const char *p;

	*maildir_file_r = FALSE;
	if ((file_id & DBOX_FILE_ID_FLAG_UID) != 0) {
		file_id &= ~DBOX_FILE_ID_FLAG_UID;
		return i_strdup_printf(DBOX_MAIL_FILE_UID_FORMAT, file_id);
	}

	rec = dbox_index_record_lookup(mbox->dbox_index, file_id);
	if (rec != NULL && rec->status == DBOX_INDEX_FILE_STATUS_MAILDIR) {
		/* data contains <uid> [<fields>] :<filename> */
		*maildir_file_r = TRUE;
		p = strstr(rec->data, " :");
		i_assert(p != NULL);
		return i_strdup_printf("%s", p + 2);
	}

	return i_strdup_printf(DBOX_MAIL_FILE_MULTI_FORMAT, file_id);
}

struct dbox_file *
dbox_file_init(struct dbox_mailbox *mbox, unsigned int file_id)
{
	const struct dbox_settings *set = mbox->storage->set;
	struct dbox_file *file;
	unsigned int count;
	bool maildir;

	file = file_id == 0 ? NULL :
		dbox_find_and_move_open_file(mbox, file_id);
	if (file != NULL) {
		file->refcount++;
		return file;
	}

	count = array_count(&mbox->open_files);
	if (count > set->dbox_max_open_files)
		dbox_close_open_files(mbox, count - set->dbox_max_open_files);

	file = i_new(struct dbox_file, 1);
	file->refcount = 1;
	file->mbox = mbox;
	if (file_id != 0) {
		file->file_id = file_id;
		file->fname = dbox_file_id_get_fname(mbox, file_id, &maildir);
		file->maildir_file = maildir;
	} else {
		file->fname = dbox_generate_tmp_filename();
	}
	if (file->maildir_file || file_id == 0) {
		/* newly created files and maildir files always exist in the
		   primary path */
		file->current_path =
			i_strdup_printf("%s/%s", mbox->path, file->fname);
	}
	file->fd = -1;

	if (file_id != 0)
		array_append(&file->mbox->open_files, &file, 1);
	return file;
}

struct dbox_file *
dbox_file_init_new_maildir(struct dbox_mailbox *mbox, const char *fname)
{
	struct dbox_file *file;

	file = dbox_file_init(mbox, 0);
	file->maildir_file = TRUE;
	file->fname = i_strdup(fname);
	return file;
}

int dbox_file_assign_id(struct dbox_file *file, unsigned int file_id)
{
	struct dbox_mailbox *mbox = file->mbox;
	const char *old_path;
	char *new_fname, *new_path;
	bool maildir;

	i_assert(file->file_id == 0);
	i_assert(file_id != 0);

	if (!file->maildir_file) {
		old_path = dbox_file_get_path(file);
		new_fname = dbox_file_id_get_fname(mbox, file_id, &maildir);
		new_path = i_strdup_printf("%s/%s", mbox->path, new_fname);

		if (rename(old_path, new_path) < 0) {
			mail_storage_set_critical(mbox->ibox.box.storage,
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
	}

	file->file_id = file_id;
	array_append(&mbox->open_files, &file, 1);
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
		files = array_get(&file->mbox->open_files, &count);
		if (!file->deleted &&
		    count <= file->mbox->storage->set->dbox_max_open_files) {
			/* we can leave this file open for now */
			return;
		}

		for (i = 0; i < count; i++) {
			if (files[i] == file)
				break;
		}
		i_assert(i != count);
		array_delete(&file->mbox->open_files, i, 1);
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
	const struct dbox_settings *set = file->mbox->storage->set;

	if (file->nonappendable)
		return FALSE;

	if (file->append_offset == 0) {
		/* messages have been expunged */
		return FALSE;
	}

	if (file->append_offset < set->dbox_rotate_min_size ||
	    file->append_offset == file->file_header_size)
		return TRUE;
	if (file->append_offset + mail_size >= set->dbox_rotate_size)
		return FALSE;
	return file->create_time >= day_begin_stamp(set->dbox_rotate_days);
}

static int dbox_file_parse_header(struct dbox_file *file, const char *line)
{
	const char *const *tmp, *value;
	unsigned int pos;
	enum dbox_header_key key;

	if (*line - '0' != DBOX_VERSION || line[1] != ' ') {
		dbox_file_set_corrupted(file, "Invalid dbox version");
		return -1;
	}
	line += 2;
	pos = 2;

	file->append_offset = 0;
	file->msg_header_size = 0;

	for (tmp = t_strsplit(line, " "); *tmp != NULL; tmp++) {
		key = **tmp;
		value = *tmp + 1;

		switch (key) {
		case DBOX_HEADER_APPEND_OFFSET:
			file->append_offset_header_pos = pos + 1;
			file->append_offset = *value == 'X' ? 0 :
				strtoull(value, NULL, 16);
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
	int i;

	/* try the primary path first */
	path = t_strdup_printf("%s/%s", file->mbox->path, file->fname);
	for (i = 0;; i++) {
		file->fd = open(path, O_RDWR);
		if (file->fd != -1)
			break;

		if (errno != ENOENT) {
			mail_storage_set_critical(file->mbox->ibox.box.storage,
						  "open(%s) failed: %m", path);
			return -1;
		}

		if (file->mbox->alt_path == NULL || i == 1) {
			/* file doesn't exist */
			return 0;
		}

		/* try the alternative path */
		path = t_strdup_printf("%s/%s", file->mbox->alt_path,
				       file->fname);
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

int dbox_create_fd(struct dbox_mailbox *mbox, const char *path)
{
	mode_t old_mask;
	int fd;

	old_mask = umask(0777 & ~mbox->ibox.box.file_create_mode);
	fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0777);
	umask(old_mask);
	if (fd == -1) {
		mail_storage_set_critical(mbox->ibox.box.storage,
			"open(%s, O_CREAT) failed: %m", path);
	}
	return fd;
}

static int dbox_file_create(struct dbox_file *file)
{
	string_t *hdr;
	const char *hdrsize;

	i_assert(file->fd == -1);

	if (file->current_path == NULL) {
		file->current_path =
			i_strdup_printf("%s/%s", file->mbox->path, file->fname);
	}
	file->fd = dbox_create_fd(file->mbox, file->current_path);
	if (file->fd == -1)
		return -1;
	file->output = o_stream_create_fd_file(file->fd, 0, FALSE);

	hdr = t_str_new(128);
	str_printfa(hdr, "%u %c%x %c%x %c", DBOX_VERSION,
		    DBOX_HEADER_MSG_HEADER_SIZE,
		    (unsigned int)sizeof(struct dbox_message_header),
		    DBOX_HEADER_CREATE_STAMP, (unsigned int)ioloop_time,
		    DBOX_HEADER_APPEND_OFFSET);
	file->append_offset_header_pos = str_len(hdr);
	str_printfa(hdr, "%08x\n", 0);

	file->file_header_size = str_len(hdr);
	file->msg_header_size = sizeof(struct dbox_message_header);
	file->append_offset = str_len(hdr);

	hdrsize = t_strdup_printf("%08x", (unsigned int)file->append_offset);
	buffer_write(hdr, file->append_offset_header_pos, hdrsize, 8);

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

	if (file->file_id == 0) {
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
		path = t_strdup_printf("%s/%s", file->mbox->path, file->fname);
		mail_storage_set_critical(file->mbox->ibox.box.storage,
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
	i_assert(file->current_path != NULL);

	return file->current_path;
}

static int
dbox_file_get_maildir_data(struct dbox_file *file, uint32_t *uid_r,
			   uoff_t *physical_size_r)
{
	struct dbox_index_record *rec;
	struct stat st;

	if (fstat(file->fd, &st) < 0) {
		dbox_file_set_syscall_error(file, "fstat");
		return -1;
	}

	rec = dbox_index_record_lookup(file->mbox->dbox_index, file->file_id);
	if (rec == NULL) {
		/* should happen only when we're rebuilding the index */
		*uid_r = 0;
	} else {
		i_assert(rec->status == DBOX_INDEX_FILE_STATUS_MAILDIR);
		*uid_r = strtoul(rec->data, NULL, 10);
	}
	*physical_size_r = st.st_size;
	return 1;
}

static int dbox_file_read_mail_header(struct dbox_file *file, uint32_t *uid_r,
				      uoff_t *physical_size_r)
{
	struct dbox_message_header hdr;
	const unsigned char *data;
	size_t size;
	int ret;

	if (file->maildir_file)
		return dbox_file_get_maildir_data(file, uid_r, physical_size_r);

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

	/* Ignore the UID header with UID files */
	*uid_r = (file->file_id & DBOX_FILE_ID_FLAG_UID) != 0 ?
		(file->file_id & ~DBOX_FILE_ID_FLAG_UID) :
		hex2dec(hdr.uid_hex, sizeof(hdr.uid_hex));
	*physical_size_r = hex2dec(hdr.message_size_hex,
				   sizeof(hdr.message_size_hex));
	return 1;
}

int dbox_file_get_mail_stream(struct dbox_file *file, uoff_t offset,
			      uint32_t *uid_r, uoff_t *physical_size_r,
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

	if (offset != file->cur_offset || file->cur_uid == 0) {
		file->cur_offset = offset;
		i_stream_seek(file->input, offset);
		ret = dbox_file_read_mail_header(file, &file->cur_uid,
						 &file->cur_physical_size);
		if (ret <= 0)
			return ret;
	}
	if (stream_r != NULL) {
		i_stream_seek(file->input, offset + file->msg_header_size);
		*stream_r = i_stream_create_limit(file->input,
						  file->cur_physical_size);
	}
	*uid_r = file->cur_uid;
	*physical_size_r = file->cur_physical_size;
	return 1;
}

static int
dbox_file_seek_next_at_metadata(struct dbox_file *file, uoff_t *offset,
				uint32_t *uid_r, uoff_t *physical_size_r)
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
		*uid_r = 0;
		*physical_size_r = 0;
		return 1;
	}

	return dbox_file_read_mail_header(file, uid_r, physical_size_r);
}

int dbox_file_seek_next(struct dbox_file *file, uoff_t *offset,
			uint32_t *uid_r, uoff_t *physical_size_r)
{
	uint32_t uid;
	uoff_t size;
	bool first = *offset == 0;
	bool deleted;
	int ret;

	ret = dbox_file_get_mail_stream(file, *offset, &uid, &size, NULL,
					&deleted);
	if (ret <= 0)
		return ret;

	if (deleted) {
		*uid_r = 0;
		*physical_size_r = 0;
		return 1;
	}
	if (first) {
		*uid_r = uid;
		*physical_size_r = size;
		return 1;
	}

	i_stream_skip(file->input, size);
	return dbox_file_seek_next_at_metadata(file, offset, uid_r,
					       physical_size_r);
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

	if (file->metadata_pool != NULL) {
		if (array_is_created(&file->metadata_changes))
			array_free(&file->metadata_changes);
		p_clear(file->metadata_pool);
	} else {
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
			file->metadata_space_pos =
				prev_offset - metadata_data_offset;
			*expunged_r = FALSE;
			break;
		}
		line = p_strdup(file->metadata_pool, line);
		array_append(&file->metadata, &line, 1);
	}
	file->metadata_read_offset = metadata_offset;
	file->metadata_len = file->input->v_offset - metadata_data_offset;
	if (*expunged_r)
		file->metadata_space_pos = file->metadata_len;
	return 1;
}

int dbox_file_metadata_seek_mail_offset(struct dbox_file *file, uoff_t offset,
					bool *expunged_r)
{
	uoff_t physical_size, metadata_offset;
	uint32_t uid;
	int ret;

	ret = dbox_file_get_mail_stream(file, offset, &uid, &physical_size,
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

void dbox_file_metadata_set(struct dbox_file *file, enum dbox_metadata_key key,
			    const char *value)
{
	const char **changes, *data;
	unsigned int i, count;

	data = file->maildir_file ? NULL : dbox_file_metadata_get(file, key);
	if (data != NULL && strcmp(data, value) == 0) {
		/* value didn't change */
		return;
	}

	data = p_strdup_printf(file->metadata_pool, "%c%s", (char)key, value);

	if (!array_is_created(&file->metadata_changes))
		p_array_init(&file->metadata_changes, file->metadata_pool, 16);
	else {
		/* see if we have already changed this metadata */
		changes = array_get_modifiable(&file->metadata_changes, &count);
		for (i = 0; i < count; i++) {
			if (*changes[i] == (char)key) {
				changes[i] = data;
				return;
			}
		}
	}

	array_append(&file->metadata_changes, &data, 1);
}

static int dbox_file_metadata_is_at_eof(struct dbox_file *file)
{
	uoff_t size;
	uint32_t uid;
	uoff_t offset;
	int ret;

	if ((file->file_id & DBOX_FILE_ID_FLAG_UID) != 0)
		return 1;

	offset = file->metadata_read_offset;
	ret = dbox_file_seek_next_at_metadata(file, &offset, &uid, &size);
	return ret <= 0 ? ret : uid == 0;
}

static int dbox_file_write_empty_block(struct dbox_file *file, uoff_t offset,
				       unsigned int len)
{
	char space[256];

	i_assert(len > 0);

	len--;
	memset(space, DBOX_METADATA_SPACE, I_MIN(sizeof(space), len));
	while (len >= sizeof(space)) {
		if (pwrite_full(file->fd, space, sizeof(space), offset) < 0) {
			dbox_file_set_syscall_error(file, "pwrite");
			return -1;
		}
	}
	/* @UNSAFE: last block ends with LF */
	space[len++] = '\n';
	if (pwrite_full(file->fd, space, len, offset) < 0) {
		dbox_file_set_syscall_error(file, "pwrite");
		return -1;
	}
	file->metadata_len += len;
	return 1;
}

static int dbox_file_grow_metadata(struct dbox_file *file, unsigned int len)
{
	enum dbox_index_file_lock_status lock_status;
	uoff_t offset;
	int ret;

	ret = dbox_index_try_lock_file(file->mbox->dbox_index, file->file_id,
				       &lock_status);
	if (ret <= 0 || (ret = dbox_file_metadata_is_at_eof(file)) <= 0)
		return ret;

	offset = file->metadata_read_offset +
		sizeof(struct dbox_metadata_header) + file->metadata_len;
	i_stream_seek(file->input, offset);
	(void)i_stream_read(file->input);
	if (!i_stream_have_bytes_left(file->input)) {
		len = len - file->metadata_len + DBOX_EXTRA_SPACE;
		ret = dbox_file_write_empty_block(file, offset, len);
	} else {
		i_error("%s: Metadata changed unexpectedly",
			dbox_file_get_path(file));
		ret = -1;
	}

	dbox_index_unlock_file(file->mbox->dbox_index, file->file_id);
	return ret;
}

static int dbox_file_metadata_write_real(struct dbox_file *file)
{
	const char *const *metadata, *const *changes;
	unsigned int i, j, count, changes_count, space_needed, skip_pos;
	char space[DBOX_EXTRA_SPACE];
	string_t *str;
	uoff_t offset;
	int ret;

	if (!array_is_created(&file->metadata_changes)) {
		/* nothing to write */
		return 1;
	}
	if (file->maildir_file)
		return 0;

	offset = file->metadata_read_offset +
		sizeof(struct dbox_metadata_header);
	metadata = array_get(&file->metadata, &count);
	changes = array_get(&file->metadata_changes, &changes_count);

	/* skip as many metadata fields from beginning as we can */
	for (i = skip_pos = 0; i < count; i++) {
		for (j = 0; j < changes_count; j++) {
			if (*changes[j] == *metadata[i])
				break;
		}
		if (j != changes_count)
			break;
		skip_pos += strlen(metadata[i]) + 1;
	}

	str = t_str_new(512);
	/* overwrite existing metadata fields */
	for (; i < count; i++) {
		for (j = 0; j < changes_count; j++) {
			if (*changes[j] == *metadata[i])
				break;
		}
		if (j != changes_count) {
			str_append(str, changes[j]);
			str_append_c(str, '\n');
		} else {
			str_append(str, metadata[i]);
			str_append_c(str, '\n');
		}
	}
	/* add new metadata */
	for (j = 0; j < changes_count; j++) {
		for (i = 0; i < count; i++) {
			if (*changes[j] == *metadata[i])
				break;
		}
		if (i == count) {
			str_append(str, changes[j]);
			str_append_c(str, '\n');
		}
	}
	if (skip_pos + str_len(str) >= file->metadata_len) {
		if ((ret = dbox_file_grow_metadata(file, skip_pos +
						   str_len(str))) <= 0)
			return ret;
	}

	memset(space, DBOX_METADATA_SPACE, sizeof(space));
	while (skip_pos + str_len(str) < file->metadata_space_pos) {
		space_needed = file->metadata_space_pos -
			(skip_pos + str_len(str));
		str_append_n(str, space, I_MIN(sizeof(space), space_needed));
	}
	i_assert(skip_pos + str_len(str) <= file->metadata_len);

	if (file->metadata_space_pos < skip_pos + str_len(str)) {
		/* metadata was grown, update space position */
		file->metadata_space_pos = skip_pos + str_len(str);
	}

	ret = pwrite_full(file->fd, str_data(str), str_len(str),
			  offset + skip_pos);
	if (ret < 0) {
		dbox_file_set_syscall_error(file, "pwrite");
		return -1;
	}
	return 1;
}

int dbox_file_metadata_write(struct dbox_file *file)
{
	int ret;

	T_BEGIN {
		ret = dbox_file_metadata_write_real(file);
	} T_END;
	return ret;
}

int dbox_file_metadata_write_to(struct dbox_file *file, struct ostream *output)
{
	struct dbox_metadata_header metadata_hdr;
	char space[DBOX_EXTRA_SPACE];
	const char *const *metadata, *const *changes;
	unsigned int i, j, count, changes_count;

	memset(&metadata_hdr, 0, sizeof(metadata_hdr));
	memcpy(metadata_hdr.magic_post, DBOX_MAGIC_POST,
	       sizeof(metadata_hdr.magic_post));
	if (o_stream_send(output, &metadata_hdr, sizeof(metadata_hdr)) < 0)
		return -1;

	metadata = array_get(&file->metadata, &count);
	if (!array_is_created(&file->metadata_changes)) {
		for (i = 0; i < count; i++) {
			if (o_stream_send_str(output, metadata[i]) < 0 ||
			    o_stream_send(output, "\n", 1) < 0)
				return -1;
		}
	} else {
		changes = array_get(&file->metadata_changes, &changes_count);
		/* write unmodified metadata */
		for (i = 0; i < count; i++) {
			for (j = 0; j < changes_count; j++) {
				if (*changes[j] == *metadata[i])
					break;
			}
			if (j == changes_count) {
				if (o_stream_send_str(output, metadata[i]) < 0)
					return -1;
				if (o_stream_send(output, "\n", 1) < 0)
					return -1;
			}
		}
		/* write modified metadata */
		for (i = 0; i < changes_count; i++) {
			if (o_stream_send_str(output, changes[i]) < 0 ||
			    o_stream_send(output, "\n", 1) < 0)
				return -1;
		}
	}

	memset(space, ' ', sizeof(space));
	if (o_stream_send(output, space, sizeof(space)) < 0 ||
	    o_stream_send(output, "\n", 1) < 0)
		return -1;
	return 0;
}

bool dbox_file_lookup(struct dbox_mailbox *mbox, struct mail_index_view *view,
		      uint32_t seq, uint32_t *file_id_r, uoff_t *offset_r)
{
	const struct dbox_mail_index_record *dbox_rec;
	const void *data;
	uint32_t uid;
	bool expunged;

	mail_index_lookup_ext(view, seq, mbox->dbox_ext_id, &data, &expunged);
	if (expunged)
		return FALSE;
	dbox_rec = data;

	if (dbox_rec == NULL || dbox_rec->file_id == 0) {
		mail_index_lookup_uid(view, seq, &uid);
		if ((uid & DBOX_FILE_ID_FLAG_UID) != 0) {
			/* something's broken, we can't handle this high UIDs */
			return FALSE;
		}
		*file_id_r = DBOX_FILE_ID_FLAG_UID | uid;
		*offset_r = 0;
	} else {
		*file_id_r = dbox_rec->file_id;
		*offset_r = dbox_rec->offset;
	}
	return TRUE;
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

	dest_dir = alt_path ? file->mbox->alt_path : file->mbox->path;
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

	if (!file->mbox->ibox.fsync_disable && ret == 0) {
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
	if (!file->mbox->ibox.fsync_disable) {
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

void dbox_mail_metadata_flags_append(string_t *str, enum mail_flags flags)
{
	unsigned int i;

	for (i = 0; i < DBOX_METADATA_FLAGS_COUNT; i++) {
		if ((flags & dbox_mail_flags_map[i]) != 0)
			str_append_c(str, dbox_mail_flag_chars[i]);
		else
			str_append_c(str, '0');
	}
}

void dbox_mail_metadata_keywords_append(struct dbox_mailbox *mbox,
					string_t *str,
					const struct mail_keywords *keywords)
{
	const ARRAY_TYPE(keywords) *keyword_names_list;
	const char *const *keyword_names;
	unsigned int i, keyword_names_count;

	if (keywords == NULL || keywords->count == 0)
		return;

	keyword_names_list = mail_index_get_keywords(mbox->ibox.index);
	keyword_names = array_get(keyword_names_list, &keyword_names_count);

	for (i = 0; i < keywords->count; i++) {
		i_assert(keywords->idx[i] < keyword_names_count);

		str_append(str, keyword_names[keywords->idx[i]]);
		str_append_c(str, ' ');
	}
	str_truncate(str, str_len(str)-1);
}

void dbox_msg_header_fill(struct dbox_message_header *dbox_msg_hdr,
			  uint32_t uid, uoff_t message_size)
{
	memset(dbox_msg_hdr, ' ', sizeof(*dbox_msg_hdr));
	memcpy(dbox_msg_hdr->magic_pre, DBOX_MAGIC_PRE,
	       sizeof(dbox_msg_hdr->magic_pre));
	dbox_msg_hdr->type = DBOX_MESSAGE_TYPE_NORMAL;
	dec2hex(dbox_msg_hdr->uid_hex, uid, sizeof(dbox_msg_hdr->uid_hex));
	dec2hex(dbox_msg_hdr->message_size_hex, message_size,
		sizeof(dbox_msg_hdr->message_size_hex));
	dbox_msg_hdr->save_lf = '\n';
}
