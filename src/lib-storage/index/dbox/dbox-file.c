/* Copyright (c) 2007-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "hex-dec.h"
#include "hex-binary.h"
#include "hostpid.h"
#include "istream.h"
#include "ostream.h"
#include "file-lock.h"
#include "mkdir-parents.h"
#include "fdatasync-path.h"
#include "eacces-error.h"
#include "str.h"
#include "dbox-storage.h"
#include "dbox-file.h"
#include "dbox-file-maildir.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>

char *dbox_generate_tmp_filename(void)
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
				  "%s failed for file %s: %m",
				  function, file->current_path);
}

void dbox_file_set_corrupted(struct dbox_file *file, const char *reason, ...)
{
	va_list args;

	if (file->single_mbox == NULL)
		file->storage->sync_rebuild = TRUE;

	va_start(args, reason);
	mail_storage_set_critical(&file->storage->storage,
		"Corrupted dbox file %s (around offset=%"PRIuUOFF_T"): %s",
		file->current_path,
		file->input == NULL ? 0 : file->input->v_offset,
		t_strdup_vprintf(reason, args));
	va_end(args);
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

void dbox_files_sync_input(struct dbox_storage *storage)
{
	struct dbox_file *const *files;
	unsigned int i, count;

	files = array_get(&storage->open_files, &count);
	for (i = 0; i < count; i++) {
		if (files[i]->input != NULL)
			i_stream_sync(files[i]->input);
	}
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

	dir = file->single_mbox != NULL ? file->single_mbox->ibox.box.path :
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
	file->cur_offset = (uoff_t)-1;
	if (uid != 0) {
		file->uid = uid;
		file->fname = dbox_file_uid_get_fname(mbox, uid, &maildir);
		file->maildir_file = maildir;
	} else {
		file->fname = dbox_generate_tmp_filename();
	}
	file->current_path = i_strdup_printf("%s/%s", mbox->ibox.box.path,
					     file->fname);
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
	if (count > storage->set->dbox_max_open_files) {
		dbox_close_open_files(storage, count -
				      storage->set->dbox_max_open_files);
	}

	file = i_new(struct dbox_file, 1);
	file->refcount = 1;
	file->storage = storage;
	file->file_id = file_id;
	file->fd = -1;
	file->cur_offset = (uoff_t)-1;
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

	old_path = file->current_path;
	if (file->single_mbox != NULL) {
		new_fname = dbox_file_uid_get_fname(file->single_mbox,
						    id, &maildir);
		new_path = i_strdup_printf("%s/%s",
					   file->single_mbox->ibox.box.path,
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
	struct dbox_file *const *files, *oldest_file;
	unsigned int i, count;

	*_file = NULL;

	i_assert(file->refcount > 0);
	if (--file->refcount > 0)
		return;

	/* don't cache metadata seeks while file isn't being referenced */
	file->metadata_read_offset = (uoff_t)-1;

	if (file->file_id != 0) {
		files = array_get(&file->storage->open_files, &count);
		if (!file->deleted &&
		    count <= file->storage->set->dbox_max_open_files) {
			/* we can leave this file open for now */
			return;
		}

		/* close the oldest file with refcount=0 */
		for (i = 0; i < count; i++) {
			if (files[i]->refcount == 0)
				break;
		}
		oldest_file = files[i];
		array_delete(&file->storage->open_files, i, 1);
		if (oldest_file != file) {
			dbox_file_free(oldest_file);
			return;
		}
		/* have to close ourself */
	}

	dbox_file_free(file);
}

static int dbox_file_parse_header(struct dbox_file *file, const char *line)
{
	const char *const *tmp, *value;
	unsigned int pos;
	enum dbox_header_key key;

	file->file_version = *line - '0';
	if (!i_isdigit(line[0]) || line[1] != ' ' ||
	    (file->file_version != 1 && file->file_version != DBOX_VERSION)) {
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
	return 0;
}

static int dbox_file_read_header(struct dbox_file *file)
{
	const char *line;
	unsigned int hdr_size;
	int ret;

	i_stream_seek(file->input, 0);
	line = i_stream_read_next_line(file->input);
	if (line == NULL) {
		if (file->input->stream_errno == 0) {
			dbox_file_set_corrupted(file,
				"EOF while reading file header");
			return 0;
		}

		dbox_file_set_syscall_error(file, "read()");
		return -1;
	}
	hdr_size = file->input->v_offset;
	T_BEGIN {
		ret = dbox_file_parse_header(file, line) < 0 ? 0 : 1;
	} T_END;
	if (ret > 0)
		file->file_header_size = hdr_size;
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

int dbox_file_open(struct dbox_file *file, bool *deleted_r)
{
	int ret;

	*deleted_r = FALSE;
	if (file->input != NULL)
		return 1;

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
	i_stream_set_init_buffer_size(file->input, MAIL_READ_BLOCK_SIZE);
	return file->maildir_file ? 1 :
		dbox_file_read_header(file);
}

int dbox_create_fd(struct dbox_storage *storage, const char *path)
{
	mode_t old_mask;
	int fd;

	old_mask = umask(0666 & ~storage->create_mode);
	fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0777);
	umask(old_mask);
	if (fd == -1) {
		mail_storage_set_critical(&storage->storage,
			"open(%s, O_CREAT) failed: %m", path);
	} else if (storage->create_gid == (gid_t)-1) {
		/* no group change */
	} else if (fchown(fd, (uid_t)-1, storage->create_gid) < 0) {
		if (errno == EPERM) {
			mail_storage_set_critical(&storage->storage, "%s",
				eperm_error_get_chgrp("fchown", path,
					storage->create_gid,
					storage->create_gid_origin));
		} else {
			mail_storage_set_critical(&storage->storage,
				"fchown(%s, -1, %ld) failed: %m",
				path, (long)storage->create_gid);
		}
		/* continue anyway */
	}
	return fd;
}

int dbox_file_header_write(struct dbox_file *file, struct ostream *output)
{
	string_t *hdr;

	hdr = t_str_new(128);
	str_printfa(hdr, "%u %c%x %c%x\n", DBOX_VERSION,
		    DBOX_HEADER_MSG_HEADER_SIZE,
		    (unsigned int)sizeof(struct dbox_message_header),
		    DBOX_HEADER_CREATE_STAMP, (unsigned int)ioloop_time);

	file->file_header_size = str_len(hdr);
	file->msg_header_size = sizeof(struct dbox_message_header);
	return o_stream_send(output, str_data(hdr), str_len(hdr));
}

static int dbox_file_create(struct dbox_file *file)
{
	i_assert(file->fd == -1);

	file->fd = dbox_create_fd(file->storage, file->current_path);
	if (file->fd == -1)
		return -1;
	file->output = o_stream_create_fd_file(file->fd, 0, FALSE);
	if (dbox_file_header_write(file, file->output) < 0) {
		dbox_file_set_syscall_error(file, "write()");
		return -1;
	}
	return 0;
}

int dbox_file_open_or_create(struct dbox_file *file, bool *deleted_r)
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
		return dbox_file_open(file, deleted_r);
}

void dbox_file_close(struct dbox_file *file)
{
	dbox_file_unlock(file);
	if (file->input != NULL)
		i_stream_unref(&file->input);
	if (file->output != NULL)
		o_stream_unref(&file->output);
	if (file->fd != -1) {
		if (close(file->fd) < 0)
			dbox_file_set_syscall_error(file, "close()");
		file->fd = -1;
	}
	file->cur_offset = (uoff_t)-1;
}

int dbox_file_try_lock(struct dbox_file *file)
{
	int ret;

	i_assert(file->fd != -1);

	ret = file_try_lock(file->fd, file->current_path, F_WRLCK,
			    FILE_LOCK_METHOD_FCNTL, &file->lock);
	if (ret < 0) {
		mail_storage_set_critical(&file->storage->storage,
			"file_try_lock(%s) failed: %m", file->current_path);
	}
	return ret;
}

void dbox_file_unlock(struct dbox_file *file)
{
	struct stat st;

	if (file->lock != NULL) {
		if (file->output != NULL) {
			i_assert(o_stream_get_buffer_used_size(file->output) == 0);
			if (fstat(file->fd, &st) == 0 &&
			    (uoff_t)st.st_size != file->output->offset)
				i_fatal("dbox file modified while locked");
			o_stream_unref(&file->output);
		}
		file_unlock(&file->lock);
	}
	if (file->input != NULL)
		i_stream_sync(file->input);
}

int dbox_file_read_mail_header(struct dbox_file *file, uoff_t *physical_size_r)
{
	struct dbox_message_header hdr;
	struct stat st;
	const unsigned char *data;
	size_t size;
	int ret;

	if (file->maildir_file) {
		if (fstat(file->fd, &st) < 0) {
			dbox_file_set_syscall_error(file, "fstat()");
			return -1;
		}
		*physical_size_r = st.st_size;
		return 1;
	}

	ret = i_stream_read_data(file->input, &data, &size,
				 file->msg_header_size - 1);
	if (ret <= 0) {
		if (file->input->stream_errno == 0) {
			/* EOF, broken offset or file truncated */
			dbox_file_set_corrupted(file, "EOF reading msg header "
						"(got %"PRIuSIZE_T"/%u bytes)",
						size, file->msg_header_size);
			return 0;
		}
		dbox_file_set_syscall_error(file, "read()");
		return -1;
	}
	memcpy(&hdr, data, I_MIN(sizeof(hdr), file->msg_header_size));
	if (memcmp(hdr.magic_pre, DBOX_MAGIC_PRE, sizeof(hdr.magic_pre)) != 0) {
		/* probably broken offset */
		dbox_file_set_corrupted(file, "msg header has bad magic value");
		return 0;
	}

	if (data[file->msg_header_size-1] != '\n') {
		dbox_file_set_corrupted(file, "msg header doesn't end with LF");
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
	uoff_t size;
	int ret;

	*expunged_r = FALSE;

	if (file->input == NULL) {
		if ((ret = dbox_file_open(file, expunged_r)) <= 0 ||
		    *expunged_r)
			return ret;
	}

	if (offset == 0)
		offset = file->file_header_size;

	if (offset != file->cur_offset) {
		i_stream_seek(file->input, offset);
		ret = dbox_file_read_mail_header(file, &size);
		if (ret <= 0)
			return ret;
		file->cur_offset = offset;
		file->cur_physical_size = size;
	}
	i_stream_seek(file->input, offset + file->msg_header_size);
	if (stream_r != NULL) {
		*stream_r = i_stream_create_limit(file->input,
						  file->cur_physical_size);
	}
	*physical_size_r = file->cur_physical_size;
	return 1;
}

static int
dbox_file_seek_next_at_metadata(struct dbox_file *file, uoff_t *offset)
{
	const char *line;
	int ret;

	i_stream_seek(file->input, *offset);
	if ((ret = dbox_file_metadata_skip_header(file)) <= 0)
		return ret;

	/* skip over the actual metadata */
	while ((line = i_stream_read_next_line(file->input)) != NULL) {
		if (*line == DBOX_METADATA_OLDV1_SPACE || *line == '\0') {
			/* end of metadata */
			break;
		}
	}
	*offset = file->input->v_offset;
	return 1;
}

void dbox_file_seek_rewind(struct dbox_file *file)
{
	file->cur_offset = (uoff_t)-1;
}

int dbox_file_seek_next(struct dbox_file *file, uoff_t *offset_r, bool *last_r)
{
	uoff_t offset, size;
	bool expunged;
	int ret;

	if (file->cur_offset == (uoff_t)-1) {
		/* first mail. we may not have read the file at all yet,
		   so set the offset afterwards. */
		offset = 0;
	} else {
		offset = file->cur_offset + file->msg_header_size +
			file->cur_physical_size;
		if ((ret = dbox_file_seek_next_at_metadata(file, &offset)) <= 0) {
			*offset_r = file->cur_offset;
			return ret;
		}
	}
	*offset_r = offset;

	if (file->input != NULL && i_stream_is_eof(file->input)) {
		*last_r = TRUE;
		return 0;
	}
	*last_r = FALSE;

	ret = dbox_file_get_mail_stream(file, offset, &size, NULL, &expunged);
	if (*offset_r == 0)
		*offset_r = file->file_header_size;
	return ret;
}

static int
dbox_file_seek_append_pos(struct dbox_file *file, uoff_t *append_offset_r)
{
	struct stat st;

	if (file->file_version != DBOX_VERSION ||
	    file->msg_header_size != sizeof(struct dbox_message_header)) {
		/* created by an incompatible version, can't append */
		return 0;
	}

	if (fstat(file->fd, &st) < 0) {
		dbox_file_set_syscall_error(file, "fstat()");
		return -1;
	}
	*append_offset_r = st.st_size;

	file->output = o_stream_create_fd_file(file->fd, 0, FALSE);
	o_stream_seek(file->output, st.st_size);
	return 1;
}

int dbox_file_get_append_stream(struct dbox_file *file, uoff_t *append_offset_r,
				struct ostream **stream_r)
{
	int ret;

	if (file->fd == -1) {
		/* creating a new file */
		i_assert(file->output == NULL);
		i_assert(file->file_id == 0 && file->uid == 0);

		if (dbox_file_create(file) < 0)
			return -1;

		if (file->single_mbox == NULL) {
			/* creating a new multi-file. even though we don't
			   need it locked while writing to it, by the time
			   we rename() it it needs to be locked. so we might
			   as well do it here. */
			if ((ret = dbox_file_try_lock(file)) <= 0) {
				if (ret < 0)
					return -1;
				mail_storage_set_critical(
					&file->storage->storage,
					"dbox: Couldn't lock created file: %s",
					file->current_path);
				return -1;
			}
		}
		i_assert(file->output != NULL);
	} else if (file->output == NULL) {
		i_assert(file->lock != NULL || file->single_mbox != NULL);

		ret = dbox_file_seek_append_pos(file, append_offset_r);
		if (ret <= 0)
			return ret;
	}

	o_stream_ref(file->output);
	*stream_r = file->output;
	return 1;
}

uoff_t dbox_file_get_next_append_offset(struct dbox_file *file)
{
	i_assert(file->output != NULL);

	return file->output->offset;
}

void dbox_file_cancel_append(struct dbox_file *file, uoff_t append_offset)
{
	(void)o_stream_flush(file->output);

	if (file->output->offset != append_offset) {
		if (ftruncate(file->fd, append_offset) < 0)
			dbox_file_set_syscall_error(file, "ftruncate()");
		o_stream_seek(file->output, append_offset);
	}
}

int dbox_file_flush_append(struct dbox_file *file)
{
	i_assert(file->output != NULL);

	if (o_stream_flush(file->output) < 0) {
		dbox_file_set_syscall_error(file, "write()");
		return -1;
	}

	if (!file->storage->storage.set->fsync_disable) {
		if (fdatasync(file->fd) < 0) {
			dbox_file_set_syscall_error(file, "fdatasync()");
			return -1;
		}
	}
	return 0;
}

int dbox_file_metadata_skip_header(struct dbox_file *file)
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
			dbox_file_set_corrupted(file,
				"Unexpected EOF while reading metadata header");
			return 0;
		}
		dbox_file_set_syscall_error(file, "read()");
		return -1;
	}
	memcpy(&metadata_hdr, data, sizeof(metadata_hdr));
	if (memcmp(metadata_hdr.magic_post, DBOX_MAGIC_POST,
		   sizeof(metadata_hdr.magic_post)) != 0) {
		/* probably broken offset */
		dbox_file_set_corrupted(file,
			"metadata header has bad magic value");
		return 0;
	}
	i_stream_skip(file->input, sizeof(metadata_hdr));
	return 1;
}

static int
dbox_file_metadata_read_at(struct dbox_file *file, uoff_t metadata_offset)
{
	const char *line;
	int ret;

	if (file->metadata_pool != NULL)
		p_clear(file->metadata_pool);
	else {
		file->metadata_pool =
			pool_alloconly_create("dbox metadata", 1024);
	}
	p_array_init(&file->metadata, file->metadata_pool, 16);

	i_stream_seek(file->input, metadata_offset);
	if ((ret = dbox_file_metadata_skip_header(file)) <= 0)
		return ret;

	ret = 0;
	while ((line = i_stream_read_next_line(file->input)) != NULL) {
		if (*line == DBOX_METADATA_OLDV1_SPACE || *line == '\0') {
			/* end of metadata */
			ret = 1;
			break;
		}
		line = p_strdup(file->metadata_pool, line);
		array_append(&file->metadata, &line, 1);
	}
	if (ret == 0)
		dbox_file_set_corrupted(file, "missing end-of-metadata line");
	return ret;
}

int dbox_file_metadata_read(struct dbox_file *file)
{
	uoff_t metadata_offset;
	int ret;

	i_assert(file->cur_offset != (uoff_t)-1);

	if (file->metadata_read_offset == file->cur_offset ||
	    file->maildir_file)
		return 1;

	metadata_offset = file->cur_offset + file->msg_header_size +
		file->cur_physical_size;
	ret = dbox_file_metadata_read_at(file, metadata_offset);
	if (ret <= 0)
		return ret;

	file->metadata_read_offset = file->cur_offset;
	return 1;
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

int dbox_file_move(struct dbox_file *file, bool alt_path)
{
	struct ostream *output;
	const char *dest_dir, *temp_path, *dest_path;
	struct stat st;
	bool deleted;
	int out_fd, ret = 0;

	i_assert(file->input != NULL);
	i_assert(file->lock != NULL);

	if (file->alt_path == alt_path)
		return 0;

	if (stat(file->current_path, &st) < 0 && errno == ENOENT) {
		/* already expunged/moved by another session */
		dbox_file_unlock(file);
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
			mail_storage_set_critical(&file->storage->storage,
				"mkdir_parents(%s) failed: %m", dest_dir);
			return -1;
		}
		out_fd = open(temp_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	}
	if (out_fd == -1) {
		mail_storage_set_critical(&file->storage->storage,
			"open(%s, O_CREAT) failed: %m", temp_path);
		return -1;
	}
	output = o_stream_create_fd_file(out_fd, 0, FALSE);
	i_stream_seek(file->input, 0);
	while ((ret = o_stream_send_istream(output, file->input)) > 0) ;
	if (ret == 0)
		ret = o_stream_flush(output);
	if (output->stream_errno != 0) {
		errno = output->stream_errno;
		mail_storage_set_critical(&file->storage->storage,
					  "write(%s) failed: %m", temp_path);
		ret = -1;
	} else if (file->input->stream_errno != 0) {
		errno = file->input->stream_errno;
		dbox_file_set_syscall_error(file, "ftruncate()");
		ret = -1;
	} else if (ret < 0) {
		mail_storage_set_critical(&file->storage->storage,
			"o_stream_send_istream(%s, %s) "
			"failed with unknown error",
			temp_path, file->current_path);
	}
	o_stream_unref(&output);

	if (!file->storage->storage.set->fsync_disable && ret == 0) {
		if (fsync(out_fd) < 0) {
			mail_storage_set_critical(&file->storage->storage,
				"fsync(%s) failed: %m", temp_path);
			ret = -1;
		}
	}
	if (close(out_fd) < 0) {
		mail_storage_set_critical(&file->storage->storage,
			"close(%s) failed: %m", temp_path);
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
		mail_storage_set_critical(&file->storage->storage,
			"rename(%s, %s) failed: %m", temp_path, dest_path);
		(void)unlink(temp_path);
		return -1;
	}
	if (!file->storage->storage.set->fsync_disable) {
		if (fdatasync_path(dest_dir) < 0) {
			mail_storage_set_critical(&file->storage->storage,
				"fdatasync(%s) failed: %m", dest_dir);
			(void)unlink(dest_path);
			return -1;
		}
	}
	if (unlink(file->current_path) < 0) {
		dbox_file_set_syscall_error(file, "unlink()");
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
	if (dbox_file_open(file, &deleted) <= 0) {
		mail_storage_set_critical(&file->storage->storage,
			"dbox_file_move(%s): reopening file failed", dest_path);
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
