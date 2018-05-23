/* Copyright (c) 2009-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "hex-dec.h"
#include "istream.h"
#include "ostream.h"
#include "message-size.h"
#include "dbox-storage.h"
#include "dbox-file.h"

#include <stdio.h>

#define DBOX_MAIL_FILE_BROKEN_COPY_SUFFIX ".broken"

static int
dbox_file_match_pre_magic(struct istream *input,
			  uoff_t *pre_offset, size_t *need_bytes)
{
	const struct dbox_message_header *hdr;
	const unsigned char *data;
	size_t size;
	uoff_t offset = input->v_offset;
	bool have_lf = FALSE;

	data = i_stream_get_data(input, &size);
	if (data[0] == '\n') {
		data++; size--; offset++;
		have_lf = TRUE;
	}
	i_assert(data[0] == DBOX_MAGIC_PRE[0]);
	if (size < sizeof(*hdr)) {
		*need_bytes = sizeof(*hdr) + (have_lf ? 1 : 0);
		return -1;
	}
	hdr = (const void *)data;
	if (memcmp(hdr->magic_pre, DBOX_MAGIC_PRE, strlen(DBOX_MAGIC_PRE)) != 0)
		return 0;
	if (hdr->type != DBOX_MESSAGE_TYPE_NORMAL)
		return 0;
	if (hdr->space1 != ' ' || hdr->space2 != ' ')
		return 0;
	if (hex2dec(hdr->message_size_hex, sizeof(hdr->message_size_hex)) == 0 &&
	    memcmp(hdr->message_size_hex, "0000000000000000", sizeof(hdr->message_size_hex)) != 0)
		return 0;

	*pre_offset = offset;
	return 1;
}

static bool memchr_nocontrol(const unsigned char *data, char chr,
			     unsigned int len, const unsigned char **pos_r)
{
	unsigned int i;

	for (i = 0; i < len; i++) {
		if (data[i] == chr) {
			*pos_r = data+i;
			return TRUE;
		}
		if (data[i] < ' ')
			return FALSE;
	}
	*pos_r = NULL;
	return TRUE;
}

static int
dbox_file_match_post_magic(struct istream *input, bool input_full,
			   size_t *need_bytes)
{
	const unsigned char *data, *p;
	size_t i, size;
	bool allow_control;

	data = i_stream_get_data(input, &size);
	if (size < strlen(DBOX_MAGIC_POST)) {
		*need_bytes = strlen(DBOX_MAGIC_POST);
		return -1;
	}
	if (memcmp(data, DBOX_MAGIC_POST, strlen(DBOX_MAGIC_POST)) != 0)
		return 0;

	/* see if the metadata block looks valid */
	for (i = strlen(DBOX_MAGIC_POST); i < size; ) {
		switch (data[i]) {
		case '\n':
			return 1;
		case DBOX_METADATA_GUID:
		case DBOX_METADATA_POP3_UIDL:
		case DBOX_METADATA_ORIG_MAILBOX:
		case DBOX_METADATA_OLDV1_KEYWORDS:
			/* these could contain anything */
			allow_control = TRUE;
			break;
		case DBOX_METADATA_POP3_ORDER:
		case DBOX_METADATA_RECEIVED_TIME:
		case DBOX_METADATA_PHYSICAL_SIZE:
		case DBOX_METADATA_VIRTUAL_SIZE:
		case DBOX_METADATA_EXT_REF:
		case DBOX_METADATA_OLDV1_EXPUNGED:
		case DBOX_METADATA_OLDV1_FLAGS:
		case DBOX_METADATA_OLDV1_SAVE_TIME:
		case DBOX_METADATA_OLDV1_SPACE:
			/* no control chars */
			allow_control = FALSE;
			break;
		default:
			if (data[i] < 'A' || data[i] > 'Z')
				return 0;
			/* unknown */
			allow_control = TRUE;
			break;
		}
		if (allow_control) {
			p = memchr(data+i, '\n', size-i);
		} else {
			if (!memchr_nocontrol(data+i, '\n', size-i, &p))
				return 0;
		}
		if (p == NULL) {
			/* LF not found - try to find the end-of-metadata LF */
			if (input_full) {
				/* can't look any further - assume it's ok */
				return 1;
			}
			*need_bytes = size+1;
			return -1;
		}
		i = p - data+1;
	}
	*need_bytes = size+1;
	return -1;
}

static int
dbox_file_find_next_magic(struct dbox_file *file, uoff_t *offset_r, bool *pre_r)
{
	/* We're scanning message bodies here, trying to find the beginning of
	   the next message. Although our magic strings are very unlikely to
	   be found in regular emails, they are much more likely when emails
	   are stored compressed.. So try to be sure we find the correct
	   magic markers. */

	struct istream *input = file->input;
	uoff_t orig_offset, pre_offset, post_offset, prev_offset;
	const unsigned char *data, *magic;
	size_t size, need_bytes, prev_need_bytes;
	int ret, match;

	*pre_r = FALSE;

	orig_offset = prev_offset = input->v_offset;
	need_bytes = strlen(DBOX_MAGIC_POST); prev_need_bytes = 0;
	while ((ret = i_stream_read_bytes(input, &data, &size, need_bytes)) > 0 ||
	       ret == -2) {
		/* search for the beginning of a potential pre/post magic */
		i_assert(size > 1);
		i_assert(prev_offset != input->v_offset ||
			 need_bytes > prev_need_bytes);
		prev_offset = input->v_offset;
		prev_need_bytes = need_bytes;

		magic = memchr(data, DBOX_MAGIC_PRE[0], size);
		if (magic == NULL) {
			i_stream_skip(input, size-1);
			need_bytes = strlen(DBOX_MAGIC_POST);
			continue;
		}
		if (magic == data && input->v_offset == orig_offset) {
			/* beginning of the file */
		} else if (magic != data && magic[-1] == '\n') {
			/* PRE/POST block? leave \n */
			i_stream_skip(input, magic-data-1);
		} else {
			i_stream_skip(input, magic-data+1);
			need_bytes = strlen(DBOX_MAGIC_POST);
			continue;
		}

		pre_offset = (uoff_t)-1;
		match = dbox_file_match_pre_magic(input, &pre_offset, &need_bytes);
		if (match < 0) {
			/* more data needed */
			if (ret == -2) {
				i_stream_skip(input, 2);
				need_bytes = strlen(DBOX_MAGIC_POST);
			}
			continue;
		}
		if (match > 0)
			*pre_r = TRUE;

		match = dbox_file_match_post_magic(input, ret == -2, &need_bytes);
		if (match < 0) {
			/* more data needed */
			if (ret == -2) {
				i_stream_skip(input, 2);
				need_bytes = strlen(DBOX_MAGIC_POST);
			}
			continue;
		}
		if (match > 0) {
			post_offset = input->v_offset;
			if (pre_offset == (uoff_t)-1 ||
			    post_offset < pre_offset) {
				pre_offset = post_offset;
				*pre_r = FALSE;
			}
		}

		if (pre_offset != (uoff_t)-1) {
			*offset_r = pre_offset;
			ret = 1;
			break;
		}
		i_stream_skip(input, size-1);
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
	return ret <= 0 ? ret : 1;
}

static int
stream_copy(struct dbox_file *file, struct ostream *output,
	    const char *out_path, uoff_t count)
{
	struct istream *input;
	int ret = 0;

	input = i_stream_create_limit(file->input, count);
	o_stream_nsend_istream(output, input);

	if (input->stream_errno != 0) {
		mail_storage_set_critical(&file->storage->storage,
			"read(%s) failed: %s", file->cur_path,
			i_stream_get_error(input));
		ret = -1;
	} else if (o_stream_flush(output) < 0) {
		mail_storage_set_critical(&file->storage->storage,
			"write(%s) failed: %s", out_path,
			o_stream_get_error(output));
		ret = -1;
	} else if (input->v_offset != count) {
		mail_storage_set_critical(&file->storage->storage,
			"o_stream_send_istream(%s) copied only %"
			PRIuUOFF_T" of %"PRIuUOFF_T" bytes",
			out_path, input->v_offset, count);
		ret = -1;
	}
	i_stream_unref(&input);
	return ret;
}

static void dbox_file_skip_broken_header(struct dbox_file *file)
{
	const size_t magic_len = strlen(DBOX_MAGIC_PRE);
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
		o_stream_nsend_str(output, line);
		o_stream_nsend_str(output, "\n");
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
	bool has_nuls;
	struct istream *body_input;
	guid_128_t guid_128;
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
			o_stream_nsend(output, &msg_hdr, sizeof(msg_hdr));
		}
		/* write msg body */
		i_assert(file->input->v_offset == body_offset);
		if (stream_copy(file, output, temp_path, msg_size) < 0)
			return -1;
		i_assert(file->input->v_offset == offset);

		/* get message body size */
		i_stream_seek(file->input, body_offset);
		body_input = i_stream_create_limit(file->input, msg_size);
		ret = message_get_body_size(body_input, &body, &has_nuls);
		i_stream_unref(&body_input);
		if (ret < 0) {
			mail_storage_set_critical(&file->storage->storage,
				"read(%s) failed: %s", file->cur_path,
				i_stream_get_error(body_input));
			return -1;
		}

		/* write msg metadata. */
		i_assert(file->input->v_offset == offset);
		ret = dbox_file_metadata_skip_header(file);
		if (ret < 0)
			return -1;
		o_stream_nsend_str(output, DBOX_MAGIC_POST);
		if (ret == 0)
			have_guid = FALSE;
		else
			dbox_file_copy_metadata(file, output, &have_guid);
		if (!have_guid) {
			guid_128_generate(guid_128);
			o_stream_nsend_str(output,
				t_strdup_printf("%c%s\n", DBOX_METADATA_GUID,
				guid_128_to_string(guid_128)));
		}
		o_stream_nsend_str(output,
			t_strdup_printf("%c%llx\n", DBOX_METADATA_VIRTUAL_SIZE,
					(unsigned long long)body.virtual_size));
		o_stream_nsend_str(output, "\n");
		if (output->stream_errno != 0)
			break;
	}
	if (o_stream_flush(output) < 0) {
		mail_storage_set_critical(&file->storage->storage,
			"write(%s) failed: %s", temp_path, o_stream_get_error(output));
		ret = -1;
	}
	return ret;
}

int dbox_file_fix(struct dbox_file *file, uoff_t start_offset)
{
	struct ostream *output;
	const char *dir, *p, *temp_path, *broken_path;
	bool deleted, have_messages;
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
	o_stream_cork(output);
	ret = dbox_file_fix_write_stream(file, start_offset, temp_path, output);
	if (ret < 0)
		o_stream_abort(output);
	have_messages = output->offset > file->file_header_size;
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
	if (!have_messages) {
		/* the resulting file has no messages. just delete the file. */
		dbox_file_close(file);
		i_unlink(temp_path);
		i_unlink(file->cur_path);
		return 0;
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
	return 1;
}
