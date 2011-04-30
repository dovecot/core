/* Copyright (c) 2007-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "hex-dec.h"
#include "hex-binary.h"
#include "hostpid.h"
#include "istream.h"
#include "ostream.h"
#include "file-lock.h"
#include "file-dotlock.h"
#include "mkdir-parents.h"
#include "eacces-error.h"
#include "str.h"
#include "dbox-storage.h"
#include "dbox-file.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>

#define DBOX_READ_BLOCK_SIZE IO_BLOCK_SIZE

#ifndef DBOX_FILE_LOCK_METHOD_FLOCK
static const struct dotlock_settings dotlock_set = {
	.stale_timeout = 60*10,
	.use_excl_lock = TRUE
};
#endif

const char *dbox_generate_tmp_filename(void)
{
	static unsigned int create_count = 0;

	return t_strdup_printf(DBOX_TEMP_FILE_PREFIX"%lu.P%sQ%uM%u.%s",
			       (unsigned long)ioloop_timeval.tv_sec, my_pid,
			       create_count++,
			       (unsigned int)ioloop_timeval.tv_usec,
			       my_hostname);
}

void dbox_file_set_syscall_error(struct dbox_file *file, const char *function)
{
	mail_storage_set_critical(&file->storage->storage,
				  "%s failed for file %s: %m",
				  function, file->cur_path);
}

void dbox_file_set_corrupted(struct dbox_file *file, const char *reason, ...)
{
	va_list args;

	va_start(args, reason);
	mail_storage_set_critical(&file->storage->storage,
		"Corrupted dbox file %s (around offset=%"PRIuUOFF_T"): %s",
		file->cur_path, file->input == NULL ? 0 : file->input->v_offset,
		t_strdup_vprintf(reason, args));
	va_end(args);

	file->storage->v.set_file_corrupted(file);
}

void dbox_file_init(struct dbox_file *file)
{
	file->refcount = 1;
	file->fd = -1;
	file->cur_offset = (uoff_t)-1;
	file->cur_path = file->primary_path;
}

void dbox_file_free(struct dbox_file *file)
{
	i_assert(file->refcount == 0);

	if (file->metadata_pool != NULL)
		pool_unref(&file->metadata_pool);
	dbox_file_close(file);
	i_free(file->primary_path);
	i_free(file->alt_path);
	i_free(file);
}

void dbox_file_unref(struct dbox_file **_file)
{
	struct dbox_file *file = *_file;

	*_file = NULL;

	i_assert(file->refcount > 0);
	if (--file->refcount == 0)
		file->storage->v.file_unrefed(file);
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

static int dbox_file_open_fd(struct dbox_file *file, bool try_altpath)
{
	const char *path;
	int flags = O_RDWR;
	bool alt = FALSE;

	/* try the primary path first */
	path = file->primary_path;
	while ((file->fd = open(path, flags)) == -1) {
		if (errno == EACCES && flags == O_RDWR) {
			flags = O_RDONLY;
			continue;
		}
		if (errno != ENOENT) {
			mail_storage_set_critical(&file->storage->storage,
						  "open(%s) failed: %m", path);
			return -1;
		}

		if (file->alt_path == NULL || alt || !try_altpath) {
			/* not found */
			return 0;
		}

		/* try the alternative path */
		path = file->alt_path;
		alt = TRUE;
	}
	file->cur_path = path;
	return 1;
}

static int dbox_file_open_full(struct dbox_file *file, bool try_altpath,
			       bool *notfound_r)
{
	int ret;

	*notfound_r = FALSE;
	if (file->input != NULL)
		return 1;

	if (file->fd == -1) {
		T_BEGIN {
			ret = dbox_file_open_fd(file, try_altpath);
		} T_END;
		if (ret <= 0) {
			if (ret < 0)
				return -1;
			*notfound_r = TRUE;
			return 1;
		}
	}

	file->input = i_stream_create_fd(file->fd, DBOX_READ_BLOCK_SIZE, FALSE);
	i_stream_set_name(file->input, file->cur_path);
	i_stream_set_init_buffer_size(file->input, DBOX_READ_BLOCK_SIZE);
	return dbox_file_read_header(file);
}

int dbox_file_open(struct dbox_file *file, bool *deleted_r)
{
	return dbox_file_open_full(file, TRUE, deleted_r);
}

int dbox_file_open_primary(struct dbox_file *file, bool *notfound_r)
{
	return dbox_file_open_full(file, FALSE, notfound_r);
}

int dbox_file_stat(struct dbox_file *file, struct stat *st_r)
{
	const char *path;
	bool alt = FALSE;

	if (dbox_file_is_open(file)) {
		if (fstat(file->fd, st_r) < 0) {
			mail_storage_set_critical(&file->storage->storage,
				"fstat(%s) failed: %m", file->cur_path);
			return -1;
		}
		return 0;
	}

	/* try the primary path first */
	path = file->primary_path;
	while (stat(path, st_r) < 0) {
		if (errno != ENOENT) {
			mail_storage_set_critical(&file->storage->storage,
						  "stat(%s) failed: %m", path);
			return -1;
		}

		if (file->alt_path == NULL || alt) {
			/* not found */
			return -1;
		}

		/* try the alternative path */
		path = file->alt_path;
		alt = TRUE;
	}
	file->cur_path = path;
	return 0;
}

int dbox_file_header_write(struct dbox_file *file, struct ostream *output)
{
	string_t *hdr;

	hdr = t_str_new(128);
	str_printfa(hdr, "%u %c%x %c%x\n", DBOX_VERSION,
		    DBOX_HEADER_MSG_HEADER_SIZE,
		    (unsigned int)sizeof(struct dbox_message_header),
		    DBOX_HEADER_CREATE_STAMP, (unsigned int)ioloop_time);

	file->file_version = DBOX_VERSION;
	file->file_header_size = str_len(hdr);
	file->msg_header_size = sizeof(struct dbox_message_header);
	return o_stream_send(output, str_data(hdr), str_len(hdr));
}

void dbox_file_close(struct dbox_file *file)
{
	dbox_file_unlock(file);
	if (file->input != NULL)
		i_stream_unref(&file->input);
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

#ifdef DBOX_FILE_LOCK_METHOD_FLOCK
	ret = file_try_lock(file->fd, file->cur_path, F_WRLCK,
			    FILE_LOCK_METHOD_FLOCK, &file->lock);
	if (ret < 0) {
		mail_storage_set_critical(&file->storage->storage,
			"file_try_lock(%s) failed: %m", file->cur_path);
	}
#else
	ret = file_dotlock_create(&dotlock_set, file->cur_path,
				  DOTLOCK_CREATE_FLAG_NONBLOCK, &file->lock);
	if (ret < 0) {
		mail_storage_set_critical(&file->storage->storage,
			"file_dotlock_create(%s) failed: %m", file->cur_path);
	}
#endif
	return ret;
}

void dbox_file_unlock(struct dbox_file *file)
{
	i_assert(!file->appending || file->lock == NULL);

	if (file->lock != NULL) {
#ifdef DBOX_FILE_LOCK_METHOD_FLOCK
		file_unlock(&file->lock);
#else
		(void)file_dotlock_delete(&file->lock);
#endif
	}
	if (file->input != NULL)
		i_stream_sync(file->input);
}

int dbox_file_read_mail_header(struct dbox_file *file, uoff_t *physical_size_r)
{
	struct dbox_message_header hdr;
	const unsigned char *data;
	size_t size;
	int ret;

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

int dbox_file_seek(struct dbox_file *file, uoff_t offset)
{
	uoff_t size;
	int ret;

	i_assert(file->input != NULL);

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
	return 1;
}

static int
dbox_file_seek_next_at_metadata(struct dbox_file *file, uoff_t *offset)
{
	const char *line;
	size_t buf_size;
	int ret;

	i_stream_seek(file->input, *offset);
	if ((ret = dbox_file_metadata_skip_header(file)) <= 0)
		return ret;

	/* skip over the actual metadata */
	buf_size = i_stream_get_max_buffer_size(file->input);
	i_stream_set_max_buffer_size(file->input, 0);
	while ((line = i_stream_read_next_line(file->input)) != NULL) {
		if (*line == DBOX_METADATA_OLDV1_SPACE || *line == '\0') {
			/* end of metadata */
			break;
		}
	}
	i_stream_set_max_buffer_size(file->input, buf_size);
	*offset = file->input->v_offset;
	return 1;
}

void dbox_file_seek_rewind(struct dbox_file *file)
{
	file->cur_offset = (uoff_t)-1;
}

int dbox_file_seek_next(struct dbox_file *file, uoff_t *offset_r, bool *last_r)
{
	uoff_t offset;
	int ret;

	i_assert(file->input != NULL);

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
		if (i_stream_is_eof(file->input)) {
			*last_r = TRUE;
			return 0;
		}
	}
	*offset_r = offset;

	*last_r = FALSE;

	ret = dbox_file_seek(file, offset);
	if (*offset_r == 0)
		*offset_r = file->file_header_size;
	return ret;
}

struct dbox_file_append_context *dbox_file_append_init(struct dbox_file *file)
{
	struct dbox_file_append_context *ctx;

	i_assert(!file->appending);

	file->appending = TRUE;

	ctx = i_new(struct dbox_file_append_context, 1);
	ctx->file = file;
	if (file->fd != -1) {
		ctx->output = o_stream_create_fd_file(file->fd, 0, FALSE);
		o_stream_cork(ctx->output);
	}
	return ctx;
}

int dbox_file_append_commit(struct dbox_file_append_context **_ctx)
{
	struct dbox_file_append_context *ctx = *_ctx;
	int ret;

	i_assert(ctx->file->appending);

	*_ctx = NULL;

	ret = dbox_file_append_flush(ctx);
	if (ctx->last_checkpoint_offset != ctx->output->offset) {
		o_stream_close(ctx->output);
		if (ftruncate(ctx->file->fd, ctx->last_checkpoint_offset) < 0) {
			dbox_file_set_syscall_error(ctx->file, "ftruncate()");
			return -1;
		}
	}
	o_stream_unref(&ctx->output);
	ctx->file->appending = FALSE;
	i_free(ctx);
	return ret;
}

void dbox_file_append_rollback(struct dbox_file_append_context **_ctx)
{
	struct dbox_file_append_context *ctx = *_ctx;
	struct dbox_file *file = ctx->file;
	bool close_file = FALSE;

	i_assert(ctx->file->appending);

	*_ctx = NULL;
	if (ctx->first_append_offset == 0) {
		/* nothing changed */
	} else if (ctx->first_append_offset == file->file_header_size) {
		/* rollbacking everything */
		if (unlink(file->cur_path) < 0)
			dbox_file_set_syscall_error(file, "unlink()");
		close_file = TRUE;
	} else {
		/* truncating only some mails */
		o_stream_close(ctx->output);
		if (ftruncate(file->fd, ctx->first_append_offset) < 0)
			dbox_file_set_syscall_error(file, "ftruncate()");
	}
	if (ctx->output != NULL)
		o_stream_unref(&ctx->output);
	i_free(ctx);

	if (close_file)
		dbox_file_close(file);
	file->appending = FALSE;
}

int dbox_file_append_flush(struct dbox_file_append_context *ctx)
{
	struct mail_storage *storage = &ctx->file->storage->storage;

	if (ctx->last_flush_offset == ctx->output->offset)
		return 0;

	if (o_stream_flush(ctx->output) < 0) {
		dbox_file_set_syscall_error(ctx->file, "write()");
		return -1;
	}

	if (storage->set->parsed_fsync_mode != FSYNC_MODE_NEVER) {
		if (fdatasync(ctx->file->fd) < 0) {
			dbox_file_set_syscall_error(ctx->file, "fdatasync()");
			return -1;
		}
	}
	ctx->last_flush_offset = ctx->output->offset;
	return 0;
}

void dbox_file_append_checkpoint(struct dbox_file_append_context *ctx)
{
	ctx->last_checkpoint_offset = ctx->output->offset;
}

int dbox_file_get_append_stream(struct dbox_file_append_context *ctx,
				struct ostream **output_r)
{
	struct dbox_file *file = ctx->file;
	struct stat st;

	if (ctx->output == NULL) {
		/* file creation had failed */
		return -1;
	}
	if (ctx->last_checkpoint_offset != ctx->output->offset) {
		/* a message was aborted. don't try appending to this
		   file anymore. */
		return -1;
	}

	if (file->file_version == 0) {
		/* newly created file, write the file header */
		if (dbox_file_header_write(file, ctx->output) < 0) {
			dbox_file_set_syscall_error(file, "write()");
			return -1;
		}
		*output_r = ctx->output;
		return 1;
	}

	/* file has existing mails */
	if (file->file_version != DBOX_VERSION ||
	    file->msg_header_size != sizeof(struct dbox_message_header)) {
		/* created by an incompatible version, can't append */
		return 0;
	}

	if (ctx->output->offset == 0) {
		/* first append to existing file. seek to eof first. */
		if (fstat(file->fd, &st) < 0) {
			dbox_file_set_syscall_error(file, "fstat()");
			return -1;
		}
		if (st.st_size < file->msg_header_size) {
			dbox_file_set_corrupted(file,
				"dbox file size too small");
			return 0;
		}
		o_stream_seek(ctx->output, st.st_size);
	}
	*output_r = ctx->output;
	return 1;
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
	size_t buf_size;
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
	buf_size = i_stream_get_max_buffer_size(file->input);
	i_stream_set_max_buffer_size(file->input, 0);
	while ((line = i_stream_read_next_line(file->input)) != NULL) {
		if (*line == DBOX_METADATA_OLDV1_SPACE || *line == '\0') {
			/* end of metadata */
			ret = 1;
			break;
		}
		line = p_strdup(file->metadata_pool, line);
		array_append(&file->metadata, &line, 1);
	}
	i_stream_set_max_buffer_size(file->input, buf_size);
	if (ret == 0)
		dbox_file_set_corrupted(file, "missing end-of-metadata line");
	return ret;
}

int dbox_file_metadata_read(struct dbox_file *file)
{
	uoff_t metadata_offset;
	int ret;

	i_assert(file->cur_offset != (uoff_t)-1);

	if (file->metadata_read_offset == file->cur_offset)
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

	metadata = array_get(&file->metadata, &count);
	for (i = 0; i < count; i++) {
		if (*metadata[i] == (char)key)
			return metadata[i] + 1;
	}
	return NULL;
}

uoff_t dbox_file_get_plaintext_size(struct dbox_file *file)
{
	const char *value;

	i_assert(file->metadata_read_offset == file->cur_offset);

	/* see if we have it in metadata */
	value = dbox_file_metadata_get(file, DBOX_METADATA_PHYSICAL_SIZE);
	if (value != NULL)
		return strtoul(value, NULL, 16);
	else {
		/* no. that means we can use the size in the header */
		return file->cur_physical_size;
	}
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

int dbox_file_unlink(struct dbox_file *file)
{
	const char *path;
	bool alt = FALSE;

	path = file->primary_path;
	while (unlink(path) < 0) {
		if (errno != ENOENT) {
			mail_storage_set_critical(&file->storage->storage,
				"unlink(%s) failed: %m", path);
			return -1;
		}
		if (file->alt_path == NULL || alt) {
			/* not found */
			return 0;
		}

		/* try the alternative path */
		path = file->alt_path;
		alt = TRUE;
	}
	return 1;
}
