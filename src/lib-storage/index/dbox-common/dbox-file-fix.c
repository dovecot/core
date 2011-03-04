/* Copyright (c) 2009-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream.h"
#include "ostream.h"
#include "str-find.h"
#include "hex-binary.h"
#include "message-size.h"
#include "dbox-storage.h"
#include "dbox-file.h"

#include <stdio.h>

#define DBOX_MAIL_FILE_BROKEN_COPY_SUFFIX ".broken"

static int
dbox_file_find_next_magic(struct dbox_file *file, uoff_t *offset_r, bool *pre_r)
{
	struct istream *input = file->input;
	struct str_find_context *pre_ctx, *post_ctx;
	uoff_t orig_offset, pre_offset, post_offset;
	const unsigned char *data;
	size_t size;
	int ret;

	*pre_r = FALSE;

	pre_ctx = str_find_init(default_pool, "\n"DBOX_MAGIC_PRE);
	post_ctx = str_find_init(default_pool, DBOX_MAGIC_POST);

	/* \n isn't part of the DBOX_MAGIC_PRE, but it always preceds it.
	   assume that at this point we've already just read the \n. when
	   scanning for it later we'll need to find the \n though. */
	str_find_more(pre_ctx, (const unsigned char *)"\n", 1);

	orig_offset = input->v_offset;
	while ((ret = i_stream_read_data(input, &data, &size, 0)) > 0) {
		pre_offset = (uoff_t)-1;
		if (str_find_more(pre_ctx, data, size)) {
			pre_offset = input->v_offset +
				str_find_get_match_end_pos(pre_ctx) -
				(strlen(DBOX_MAGIC_PRE) + 1);
			*pre_r = TRUE;
		}
		if (str_find_more(post_ctx, data, size)) {
			post_offset = input->v_offset +
				str_find_get_match_end_pos(post_ctx) -
				strlen(DBOX_MAGIC_POST);
			if (pre_offset == (uoff_t)-1 ||
			    post_offset < pre_offset) {
				pre_offset = post_offset;
				*pre_r = FALSE;
			}
		}

		if (pre_offset != (uoff_t)-1) {
			if (*pre_r) {
				/* LF isn't part of the magic */
				pre_offset++;
			}
			*offset_r = pre_offset;
			break;
		}
		i_stream_skip(input, size);
	}
	if (ret <= 0) {
		i_assert(ret == -1);
		if (input->stream_errno != 0)
			dbox_file_set_syscall_error(file, "read()");
		else {
			ret = 0;
			*offset_r = input->v_offset;
		} 
	}
	i_stream_seek(input, orig_offset);
	str_find_deinit(&pre_ctx);
	str_find_deinit(&post_ctx);
	return ret;
}

static int
stream_copy(struct dbox_file *file, struct ostream *output,
	    const char *path, uoff_t count)
{
	struct istream *input;
	off_t bytes;

	input = i_stream_create_limit(file->input, count);
	bytes = o_stream_send_istream(output, input);
	i_stream_unref(&input);

	if (bytes < 0) {
		mail_storage_set_critical(&file->storage->storage,
			"o_stream_send_istream(%s, %s) failed: %m",
			file->cur_path, path);
		return -1;
	}
	if ((uoff_t)bytes != count) {
		mail_storage_set_critical(&file->storage->storage,
			"o_stream_send_istream(%s) copied only %"
			PRIuUOFF_T" of %"PRIuUOFF_T" bytes",
			path, bytes, count);
		return -1;
	}
	return 0;
}

static void dbox_file_skip_broken_header(struct dbox_file *file)
{
	const unsigned int magic_len = strlen(DBOX_MAGIC_PRE);
	const unsigned char *data;
	size_t i, size;

	/* if there's LF close to our position, assume that the header ends
	   there. */
	data = i_stream_get_data(file->input, &size);
	if (size > file->msg_header_size + 16)
		size = file->msg_header_size + 16;
	for (i = 0; i < size; i++) {
		if (data[i] == '\n') {
			i_stream_skip(file->input, i);
			return;
		}
	}

	/* skip at least the magic bytes if possible */
	if (size > magic_len && memcmp(data, DBOX_MAGIC_PRE, magic_len) == 0)
		i_stream_skip(file->input, magic_len);
}

static void
dbox_file_copy_metadata(struct dbox_file *file, struct ostream *output,
			bool *have_guid_r)
{
	const char *line;
	uoff_t prev_offset = file->input->v_offset;

	*have_guid_r = FALSE;
	while ((line = i_stream_read_next_line(file->input)) != NULL) {
		if (*line == DBOX_METADATA_OLDV1_SPACE || *line == '\0') {
			/* end of metadata */
			return;
		}
		if (*line < 32) {
			/* broken - possibly a new pre-magic block */
			i_stream_seek(file->input, prev_offset);
			return;
		}
		if (*line == DBOX_METADATA_VIRTUAL_SIZE) {
			/* it may be wrong - recreate it */
			continue;
		}
		if (*line == DBOX_METADATA_GUID)
			*have_guid_r = TRUE;
		o_stream_send_str(output, line);
		o_stream_send_str(output, "\n");
	}
}

static int
dbox_file_fix_write_stream(struct dbox_file *file, uoff_t start_offset,
			   const char *temp_path, struct ostream *output)
{
	struct dbox_message_header msg_hdr;
	uoff_t offset, msg_size, hdr_offset, body_offset;
	bool pre, write_header, have_guid;
	struct message_size body;
	struct istream *body_input;
	uint8_t guid_128[MAIL_GUID_128_SIZE];
	int ret;

	i_stream_seek(file->input, 0);
	if (start_offset > 0) {
		/* copy the valid data */
		if (stream_copy(file, output, temp_path, start_offset) < 0)
			return -1;
	} else {
		/* the file header is broken. recreate it */
		if (dbox_file_header_write(file, output) < 0) {
			dbox_file_set_syscall_error(file, "write()");
			return -1;
		}
	}

	while ((ret = dbox_file_find_next_magic(file, &offset, &pre)) > 0) {
		msg_size = offset - file->input->v_offset;
		if (msg_size < 256 && pre) {
			/* probably some garbage or some broken headers.
			   we most likely don't miss anything by skipping
			   over this data. */
			i_stream_skip(file->input, msg_size);
			hdr_offset = file->input->v_offset;
			ret = dbox_file_read_mail_header(file, &msg_size);
			if (ret <= 0) {
				if (ret < 0)
					return -1;
				dbox_file_skip_broken_header(file);
				body_offset = file->input->v_offset;
				msg_size = (uoff_t)-1;
			} else {
				i_stream_skip(file->input,
					      file->msg_header_size);
				body_offset = file->input->v_offset;
				i_stream_skip(file->input, msg_size);
			}

			ret = dbox_file_find_next_magic(file, &offset, &pre);
			if (ret <= 0)
				break;

			if (!pre && msg_size == offset - body_offset) {
				/* msg header ok, copy it */
				i_stream_seek(file->input, hdr_offset);
				if (stream_copy(file, output, temp_path,
						file->msg_header_size) < 0)
					return -1;
				write_header = FALSE;
			} else {
				/* msg header is broken. write our own. */
				i_stream_seek(file->input, body_offset);
				if (msg_size != (uoff_t)-1) {
					/* previous magic find might have
					   skipped too much. seek back and
					   make sure */
					ret = dbox_file_find_next_magic(file, &offset, &pre);
					if (ret <= 0)
						break;
				}

				write_header = TRUE;
				msg_size = offset - body_offset;
			}
		} else {
			/* treat this data as a separate message. */
			write_header = TRUE;
			body_offset = file->input->v_offset;
		}
		/* write msg header */
		if (write_header) {
			dbox_msg_header_fill(&msg_hdr, msg_size);
			(void)o_stream_send(output, &msg_hdr, sizeof(msg_hdr));
		}
		/* write msg body */
		i_assert(file->input->v_offset == body_offset);
		if (stream_copy(file, output, temp_path, msg_size) < 0)
			return -1;
		i_assert(file->input->v_offset == offset);

		/* get message body size */
		i_stream_seek(file->input, body_offset);
		body_input = i_stream_create_limit(file->input, msg_size);
		ret = message_get_body_size(body_input, &body, NULL);
		i_stream_unref(&body_input);
		if (ret < 0) {
			errno = output->stream_errno;
			mail_storage_set_critical(&file->storage->storage,
				"read(%s) failed: %m", file->cur_path);
			return -1;
		}

		/* write msg metadata. */
		i_assert(file->input->v_offset == offset);
		ret = dbox_file_metadata_skip_header(file);
		if (ret < 0)
			return -1;
		o_stream_send_str(output, DBOX_MAGIC_POST);
		if (ret == 0)
			have_guid = FALSE;
		else
			dbox_file_copy_metadata(file, output, &have_guid);
		if (!have_guid) {
			mail_generate_guid_128(guid_128);
			o_stream_send_str(output,
				t_strdup_printf("%c%s\n", DBOX_METADATA_GUID,
				binary_to_hex(guid_128, sizeof(guid_128))));
		}
		o_stream_send_str(output,
			t_strdup_printf("%c%llx\n", DBOX_METADATA_VIRTUAL_SIZE,
					(unsigned long long)body.virtual_size));
		o_stream_send_str(output, "\n");
		if (output->stream_errno != 0) {
			errno = output->stream_errno;
			mail_storage_set_critical(&file->storage->storage,
				"write(%s) failed: %m", temp_path);
			return -1;
		}
	}
	return ret;
}

int dbox_file_fix(struct dbox_file *file, uoff_t start_offset)
{
	struct ostream *output;
	const char *dir, *p, *temp_path, *broken_path;
	bool deleted;
	int fd, ret;

	i_assert(dbox_file_is_open(file));

	p = strrchr(file->cur_path, '/');
	i_assert(p != NULL);
	dir = t_strdup_until(file->cur_path, p);

	temp_path = t_strdup_printf("%s/%s", dir, dbox_generate_tmp_filename());
	fd = file->storage->v.file_create_fd(file, temp_path, FALSE);
	if (fd == -1)
		return -1;

	output = o_stream_create_fd_file(fd, 0, FALSE);
	ret = dbox_file_fix_write_stream(file, start_offset, temp_path, output);
	o_stream_unref(&output);
	if (close(fd) < 0) {
		mail_storage_set_critical(&file->storage->storage,
					  "close(%s) failed: %m", temp_path);
		ret = -1;
	}
	if (ret < 0) {
		if (unlink(temp_path) < 0) {
			mail_storage_set_critical(&file->storage->storage,
				"unlink(%s) failed: %m", temp_path);
		}
		return -1;
	}
	/* keep a copy of the original file in case someone wants to look
	   at it */
	broken_path = t_strconcat(file->cur_path,
				  DBOX_MAIL_FILE_BROKEN_COPY_SUFFIX, NULL);
	if (link(file->cur_path, broken_path) < 0) {
		mail_storage_set_critical(&file->storage->storage,
					  "link(%s, %s) failed: %m",
					  file->cur_path, broken_path);
	} else {
		i_warning("dbox: Copy of the broken file saved to %s",
			  broken_path);
	}
	if (rename(temp_path, file->cur_path) < 0) {
		mail_storage_set_critical(&file->storage->storage,
					  "rename(%s, %s) failed: %m",
					  temp_path, file->cur_path);
		return -1;
	}

	/* file was successfully recreated - reopen it */
	dbox_file_close(file);
	if (dbox_file_open(file, &deleted) <= 0) {
		mail_storage_set_critical(&file->storage->storage,
			"dbox_file_fix(%s): reopening file failed",
			file->cur_path);
		return -1;
	}
	return 0;
}
