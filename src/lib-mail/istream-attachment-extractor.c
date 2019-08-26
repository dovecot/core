/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream-private.h"
#include "ostream.h"
#include "base64.h"
#include "buffer.h"
#include "str.h"
#include "hash-format.h"
#include "rfc822-parser.h"
#include "message-parser.h"
#include "istream-attachment-extractor.h"

#define BASE64_ATTACHMENT_MAX_EXTRA_BYTES 1024

enum mail_attachment_state {
	MAIL_ATTACHMENT_STATE_NO,
	MAIL_ATTACHMENT_STATE_MAYBE,
	MAIL_ATTACHMENT_STATE_YES
};

enum base64_state {
	BASE64_STATE_0 = 0,
	BASE64_STATE_1,
	BASE64_STATE_2,
	BASE64_STATE_3,
	BASE64_STATE_CR,
	BASE64_STATE_EOB,
	BASE64_STATE_EOM
};

struct attachment_istream_part {
	char *content_type, *content_disposition;
	enum mail_attachment_state state;
	/* start offset of the message part in the original input stream */
	uoff_t start_offset;

	/* for saving attachments base64-decoded: */
	enum base64_state base64_state;
	unsigned int base64_line_blocks, cur_base64_blocks;
	uoff_t base64_bytes;
	bool base64_have_crlf; /* CRLF linefeeds */
	bool base64_failed;

	int temp_fd;
	struct ostream *temp_output;
	buffer_t *part_buf;
};

struct attachment_istream {
	struct istream_private istream;
	pool_t pool;

	struct istream_attachment_settings set;
	void *context;

	struct message_parser_ctx *parser;
	struct message_part *cur_part;
	struct attachment_istream_part part;

	bool retry_read;
};

static void stream_add_data(struct attachment_istream *astream,
			    const void *data, size_t size)
{
	if (size > 0) {
		memcpy(i_stream_alloc(&astream->istream, size), data, size);
		astream->istream.pos += size;
	}
}

static void parse_content_type(struct attachment_istream *astream,
			       const struct message_header_line *hdr)
{
	struct rfc822_parser_context parser;
	string_t *content_type;

	if (astream->part.content_type != NULL)
		return;

	rfc822_parser_init(&parser, hdr->full_value, hdr->full_value_len, NULL);
	rfc822_skip_lwsp(&parser);

	T_BEGIN {
		content_type = t_str_new(64);
		(void)rfc822_parse_content_type(&parser, content_type);
		astream->part.content_type = i_strdup(str_c(content_type));
	} T_END;
	rfc822_parser_deinit(&parser);
}

static void
parse_content_disposition(struct attachment_istream *astream,
			  const struct message_header_line *hdr)
{
	/* just pass it without parsing to is_attachment() callback */
	i_free(astream->part.content_disposition);
	astream->part.content_disposition =
		i_strndup(hdr->full_value, hdr->full_value_len);
}

static void astream_parse_header(struct attachment_istream *astream,
				 struct message_header_line *hdr)
{
	if (!hdr->continued) {
		stream_add_data(astream, hdr->name, hdr->name_len);
		stream_add_data(astream, hdr->middle, hdr->middle_len);
	}
	stream_add_data(astream, hdr->value, hdr->value_len);
	if (!hdr->no_newline) {
		if (hdr->crlf_newline)
			stream_add_data(astream, "\r\n", 2);
		else
			stream_add_data(astream, "\n", 1);
	}

	if (hdr->continues) {
		hdr->use_full_value = TRUE;
		return;
	}

	if (strcasecmp(hdr->name, "Content-Type") == 0)
		parse_content_type(astream, hdr);
	else if (strcasecmp(hdr->name, "Content-Disposition") == 0)
		parse_content_disposition(astream, hdr);
}

static bool astream_want_attachment(struct attachment_istream *astream,
				    struct message_part *part)
{
	struct istream_attachment_header ahdr;

	if ((part->flags & MESSAGE_PART_FLAG_MULTIPART) != 0) {
		/* multiparts may contain attachments as children,
		   but they're never themselves */
		return FALSE;
	}
	if (astream->set.want_attachment == NULL)
		return TRUE;

	i_zero(&ahdr);
	ahdr.part = part;
	ahdr.content_type = astream->part.content_type;
	ahdr.content_disposition = astream->part.content_disposition;
	return astream->set.want_attachment(&ahdr, astream->context);
}

static int astream_base64_decode_lf(struct attachment_istream_part *part)
{
	if (part->base64_have_crlf && part->base64_state != BASE64_STATE_CR) {
		/* mixed LF vs CRLFs */
		return -1;
	}
	part->base64_state = BASE64_STATE_0;
	if (part->cur_base64_blocks < part->base64_line_blocks) {
		/* last line */
		part->base64_state = BASE64_STATE_EOM;
		return 0;
	} else if (part->base64_line_blocks == 0) {
		/* first line */
		if (part->cur_base64_blocks == 0)
			return -1;
		part->base64_line_blocks = part->cur_base64_blocks;
	} else if (part->cur_base64_blocks == part->base64_line_blocks) {
		/* line is ok */
	} else {
		return -1;
	}
	part->cur_base64_blocks = 0;
	return 1;
}

static int
astream_try_base64_decode_char(struct attachment_istream_part *part,
			       size_t pos, char chr)
{
	switch (part->base64_state) {
	case BASE64_STATE_0:
		if (base64_is_valid_char(chr))
			part->base64_state++;
		else if (chr == '\r')
			part->base64_state = BASE64_STATE_CR;
		else if (chr == '\n') {
			return astream_base64_decode_lf(part);
		} else {
			return -1;
		}
		break;
	case BASE64_STATE_1:
		if (!base64_is_valid_char(chr))
			return -1;
		part->base64_state++;
		break;
	case BASE64_STATE_2:
		if (base64_is_valid_char(chr))
			part->base64_state++;
		else if (chr == '=')
			part->base64_state = BASE64_STATE_EOB;
		else
			return -1;
		break;
	case BASE64_STATE_3:
		part->base64_bytes = part->temp_output->offset + pos + 1;
		if (base64_is_valid_char(chr)) {
			part->base64_state = BASE64_STATE_0;
			part->cur_base64_blocks++;
		} else if (chr == '=') {
			part->base64_state = BASE64_STATE_EOM;
			part->cur_base64_blocks++;

			if (part->cur_base64_blocks > part->base64_line_blocks &&
			    part->base64_line_blocks > 0) {
				/* too many blocks */
				return -1;
			}
			return 0;
		} else {
			return -1;
		}
		break;
	case BASE64_STATE_CR:
		if (chr != '\n')
			return -1;
		if (!part->base64_have_crlf) {
			if (part->base64_line_blocks != 0) {
				/* mixed LF vs CRLFs */
				return -1;
			}
			part->base64_have_crlf = TRUE;
		}
		return astream_base64_decode_lf(part);
	case BASE64_STATE_EOB:
		if (chr != '=')
			return -1;

		part->base64_bytes = part->temp_output->offset + pos + 1;
		part->base64_state = BASE64_STATE_EOM;
		part->cur_base64_blocks++;

		if (part->cur_base64_blocks > part->base64_line_blocks &&
		    part->base64_line_blocks > 0) {
			/* too many blocks */
			return -1;
		}
		return 0;
	case BASE64_STATE_EOM:
		i_unreached();
	}
	return 1;
}

static void
astream_try_base64_decode(struct attachment_istream_part *part,
			  const unsigned char *data, size_t size)
{
	size_t i;
	int ret;

	if (part->base64_failed || part->base64_state == BASE64_STATE_EOM)
		return;

	for (i = 0; i < size; i++) {
		ret = astream_try_base64_decode_char(part, i, (char)data[i]);
		if (ret <= 0) {
			if (ret < 0)
				part->base64_failed = TRUE;
			break;
		}
	}
}

static int astream_open_output(struct attachment_istream *astream)
{
	int fd;

	i_assert(astream->part.temp_fd == -1);

	fd = astream->set.open_temp_fd(astream->context);
	if (fd == -1)
		return -1;

	astream->part.temp_fd = fd;
	astream->part.temp_output = o_stream_create_fd(fd, 0);
	o_stream_cork(astream->part.temp_output);
	return 0;
}

static void astream_add_body(struct attachment_istream *astream,
			     const struct message_block *block)
{
	struct attachment_istream_part *part = &astream->part;
	buffer_t *part_buf;
	size_t new_size;

	switch (part->state) {
	case MAIL_ATTACHMENT_STATE_NO:
		stream_add_data(astream, block->data, block->size);
		break;
	case MAIL_ATTACHMENT_STATE_MAYBE:
		/* we'll write data to in-memory buffer until we reach
		   attachment min_size */
		if (part->part_buf == NULL) {
			part->part_buf =
				buffer_create_dynamic(default_pool,
						      astream->set.min_size);
		}
		part_buf = part->part_buf;
		new_size = part_buf->used + block->size;
		if (new_size < astream->set.min_size) {
			buffer_append(part_buf, block->data, block->size);
			break;
		}
		/* attachment is large enough. we'll first copy the buffered
		   data from memory to temp file */
		if (astream_open_output(astream) < 0) {
			/* failed, fallback to just saving it inline */
			part->state = MAIL_ATTACHMENT_STATE_NO;
			stream_add_data(astream, part_buf->data, part_buf->used);
			stream_add_data(astream, block->data, block->size);
			break;
		}
		part->state = MAIL_ATTACHMENT_STATE_YES;
		astream_try_base64_decode(part, part_buf->data, part_buf->used);
		hash_format_loop(astream->set.hash_format,
				 part_buf->data, part_buf->used);
		o_stream_nsend(part->temp_output,
			       part_buf->data, part_buf->used);
		buffer_set_used_size(part_buf, 0);
		/* fall through - write the new data to temp file */
	case MAIL_ATTACHMENT_STATE_YES:
		astream_try_base64_decode(part, block->data, block->size);
		hash_format_loop(astream->set.hash_format,
				 block->data, block->size);
		o_stream_nsend(part->temp_output, block->data, block->size);
		break;
	}
}

static int astream_decode_base64(struct attachment_istream *astream,
				 buffer_t **extra_buf_r)
{
	struct attachment_istream_part *part = &astream->part;
	struct base64_decoder b64dec;
	struct istream *input, *base64_input;
	struct ostream *output;
	const unsigned char *data;
	size_t size;
	ssize_t ret;
	buffer_t *buf;
	int outfd;
	bool failed = FALSE;

	*extra_buf_r = NULL;

	if (part->base64_bytes < astream->set.min_size ||
	    part->temp_output->offset > part->base64_bytes +
	    				BASE64_ATTACHMENT_MAX_EXTRA_BYTES) {
		/* only a small part of the MIME part is base64-encoded. */
		return -1;
	}

	if (part->base64_line_blocks == 0) {
		/* only one line of base64 */
		part->base64_line_blocks = part->cur_base64_blocks;
		i_assert(part->base64_line_blocks > 0);
	}

	/* decode base64 data and write it to another temp file */
	outfd = astream->set.open_temp_fd(astream->context);
	if (outfd == -1)
		return -1;

	buf = buffer_create_dynamic(default_pool, 1024);
	input = i_stream_create_fd(part->temp_fd, IO_BLOCK_SIZE);
	base64_input = i_stream_create_limit(input, part->base64_bytes);
	output = o_stream_create_fd_file(outfd, 0, FALSE);
	o_stream_cork(output);

	base64_decode_init(&b64dec, &base64_scheme, 0);
	hash_format_reset(astream->set.hash_format);
	size_t bytes_needed = 1;
	while ((ret = i_stream_read_bytes(base64_input, &data, &size,
					  bytes_needed)) > 0) {
		buffer_set_used_size(buf, 0);
		if (base64_decode_more(&b64dec, data, size, &size, buf) < 0) {
			i_error("istream-attachment: BUG: "
				"Attachment base64 data unexpectedly broke");
			failed = TRUE;
			break;
		}
		i_stream_skip(base64_input, size);
		o_stream_nsend(output, buf->data, buf->used);
		hash_format_loop(astream->set.hash_format,
				 buf->data, buf->used);
		bytes_needed = i_stream_get_data_size(base64_input) + 1;
	}
	if (ret != -1) {
		i_assert(failed);
	} else if (base64_input->stream_errno != 0) {
		i_error("istream-attachment: read(%s) failed: %s",
			i_stream_get_name(base64_input),
			i_stream_get_error(base64_input));
		failed = TRUE;
	}
	if (base64_decode_finish(&b64dec) < 0) {
		i_error("istream-attachment: BUG: "
			"Attachment base64 data unexpectedly broke");
		failed = TRUE;
	}
	if (o_stream_finish(output) < 0) {
		i_error("istream-attachment: write(%s) failed: %s",
			o_stream_get_name(output), o_stream_get_error(output));
		failed = TRUE;
	}

	buffer_free(&buf);
	i_stream_unref(&base64_input);
	o_stream_unref(&output);

	if (input->v_offset != part->temp_output->offset && !failed) {
		/* write the rest of the data to the message stream */
		*extra_buf_r = buffer_create_dynamic(default_pool, 1024);
		while ((ret = i_stream_read_more(input, &data, &size)) > 0) {
			buffer_append(*extra_buf_r, data, size);
			i_stream_skip(input, size);
		}
		i_assert(ret == -1);
		if (input->stream_errno != 0) {
			i_error("istream-attachment: read(%s) failed: %s",
				i_stream_get_name(input),
				i_stream_get_error(input));
			failed = TRUE;
		}
	}
	i_stream_unref(&input);

	if (failed) {
		i_close_fd(&outfd);
		return -1;
	}

	/* successfully wrote it. switch to using it. */
	o_stream_destroy(&part->temp_output);
	i_close_fd(&part->temp_fd);
	part->temp_fd = outfd;
	return 0;
}

static int
astream_part_finish(struct attachment_istream *astream, const char **error_r)
{
	struct attachment_istream_part *part = &astream->part;
	struct istream_attachment_info info;
	struct istream *input;
	struct ostream *output;
	string_t *digest_str;
	buffer_t *extra_buf = NULL;
	const unsigned char *data;
	size_t size;
	int ret = 0;

	if (o_stream_finish(part->temp_output) < 0) {
		*error_r = t_strdup_printf("write(%s) failed: %s",
					   o_stream_get_name(part->temp_output),
					   o_stream_get_error(part->temp_output));
		return -1;
	}

	i_zero(&info);
	info.start_offset = astream->part.start_offset;
	/* base64_bytes contains how many valid base64 bytes there are so far.
	   if the base64 ends properly, it'll specify how much of the MIME part
	   is saved as an attachment. the rest of the data (typically
	   linefeeds) is added back to main stream */
	info.encoded_size = part->base64_bytes;
	/* get the hash before base64-decoder resets it */
	digest_str = t_str_new(128);
	hash_format_write(astream->set.hash_format, digest_str);
	info.hash = str_c(digest_str);

	/* if it looks like we can decode base64 without any data loss,
	   do it and write the decoded data to another temp file. */
	if (!part->base64_failed) {
		if (part->base64_state == BASE64_STATE_0 &&
		    part->base64_bytes > 0) {
			/* there is no trailing LF or '=' characters,
			   but it's not completely empty */
			part->base64_state = BASE64_STATE_EOM;
		}
		if (part->base64_state == BASE64_STATE_EOM) {
			/* base64 data looks ok. */
			if (astream_decode_base64(astream, &extra_buf) < 0)
				part->base64_failed = TRUE;
		} else {
			part->base64_failed = TRUE;
		}
	}

	/* open attachment output file */
	info.part = astream->cur_part;
	if (!part->base64_failed) {
		info.base64_blocks_per_line = part->base64_line_blocks;
		info.base64_have_crlf = part->base64_have_crlf;
		/* base64-decoder updated the hash, use it */
		str_truncate(digest_str, 0);
		hash_format_write(astream->set.hash_format, digest_str);
		info.hash = str_c(digest_str);
	} else {
		/* couldn't decode base64, so write the entire MIME part
		   as attachment */
		info.encoded_size = part->temp_output->offset;
	}
	if (astream->set.open_attachment_ostream(&info, &output, error_r,
						 astream->context) < 0) {
		buffer_free(&extra_buf);
		return -1;
	}

	/* copy data to attachment from temp file */
	input = i_stream_create_fd(part->temp_fd, IO_BLOCK_SIZE);
	while (i_stream_read_more(input, &data, &size) > 0) {
		o_stream_nsend(output, data, size);
		i_stream_skip(input, size);
	}

	if (input->stream_errno != 0) {
		*error_r = t_strdup_printf("read(%s) failed: %s",
			i_stream_get_name(input), i_stream_get_error(input));
		ret = -1;
	}
	i_stream_destroy(&input);

	if (astream->set.close_attachment_ostream(output, ret == 0, error_r,
						  astream->context) < 0)
		ret = -1;
	if (ret == 0 && extra_buf != NULL)
		stream_add_data(astream, extra_buf->data, extra_buf->used);
	buffer_free(&extra_buf);
	return ret;
}

static void astream_part_reset(struct attachment_istream *astream)
{
	struct attachment_istream_part *part = &astream->part;

	o_stream_destroy(&part->temp_output);
	i_close_fd(&part->temp_fd);

	i_free_and_null(part->content_type);
	i_free_and_null(part->content_disposition);
	buffer_free(&part->part_buf);

	i_zero(part);
	part->temp_fd = -1;
	hash_format_reset(astream->set.hash_format);
}

static int
astream_end_of_part(struct attachment_istream *astream, const char **error_r)
{
	struct attachment_istream_part *part = &astream->part;
	size_t old_size;
	int ret = 0;

	/* MIME part changed. we're now parsing the end of a boundary,
	   possibly followed by message epilogue */
	switch (part->state) {
	case MAIL_ATTACHMENT_STATE_NO:
		break;
	case MAIL_ATTACHMENT_STATE_MAYBE:
		/* MIME part wasn't large enough to be an attachment */
		if (part->part_buf != NULL) {
			stream_add_data(astream, part->part_buf->data,
					part->part_buf->used);
			ret = part->part_buf->used > 0 ? 1 : 0;
		}
		break;
	case MAIL_ATTACHMENT_STATE_YES:
		old_size = astream->istream.pos - astream->istream.skip;
		if (astream_part_finish(astream, error_r) < 0)
			ret = -1;
		else {
			/* finished base64 may have added a few more trailing
			   bytes to the stream */
			ret = astream->istream.pos -
				astream->istream.skip - old_size;
		}
		break;
	}
	part->state = MAIL_ATTACHMENT_STATE_NO;
	astream_part_reset(astream);
	return ret;
}

static int astream_read_next(struct attachment_istream *astream, bool *retry_r)
{
	struct istream_private *stream = &astream->istream;
	struct message_block block;
	size_t old_size, new_size;
	const char *error;
	int ret;

	*retry_r = FALSE;

	if (stream->pos - stream->skip >= i_stream_get_max_buffer_size(&stream->istream))
		return -2;

	old_size = stream->pos - stream->skip;
	switch (message_parser_parse_next_block(astream->parser, &block)) {
	case -1:
		/* done / error */
		ret = astream_end_of_part(astream, &error);
		if (ret > 0) {
			/* final data */
			new_size = stream->pos - stream->skip;
			return new_size - old_size;
		}
		stream->istream.eof = TRUE;
		stream->istream.stream_errno = stream->parent->stream_errno;

		if (ret < 0) {
			io_stream_set_error(&stream->iostream, "%s", error);
			stream->istream.stream_errno = EIO;
		}
		astream->cur_part = NULL;
		return -1;
	case 0:
		/* need more data */
		return 0;
	default:
		break;
	}

	if (block.part != astream->cur_part && astream->cur_part != NULL) {
		/* end of a MIME part */
		if (astream_end_of_part(astream, &error) < 0) {
			io_stream_set_error(&stream->iostream, "%s", error);
			stream->istream.stream_errno = EIO;
			return -1;
		}
	}
	astream->cur_part = block.part;

	if (block.hdr != NULL) {
		/* parsing a header */
		astream_parse_header(astream, block.hdr);
	} else if (block.size == 0) {
		/* end of headers */
		if (astream_want_attachment(astream, block.part)) {
			astream->part.state = MAIL_ATTACHMENT_STATE_MAYBE;
			astream->part.start_offset = stream->parent->v_offset;
		}
	} else {
		astream_add_body(astream, &block);
	}
	new_size = stream->pos - stream->skip;
	*retry_r = new_size == old_size;
	return new_size - old_size;
}

static ssize_t
i_stream_attachment_extractor_read(struct istream_private *stream)
{
	struct attachment_istream *astream =
		(struct attachment_istream *)stream;
	bool retry;
	ssize_t ret;

	do {
		ret = astream_read_next(astream, &retry);
	} while (retry && astream->set.drain_parent_input);

	astream->retry_read = retry;
	return ret;
}

static void i_stream_attachment_extractor_close(struct iostream_private *stream,
						bool close_parent)
{
	struct attachment_istream *astream =
		(struct attachment_istream *)stream;
	struct message_part *parts;

	if (astream->parser != NULL) {
		message_parser_deinit(&astream->parser, &parts);
	}
	hash_format_deinit_free(&astream->set.hash_format);
	pool_unref(&astream->pool);
	if (close_parent)
		i_stream_close(astream->istream.parent);
}

struct istream *
i_stream_create_attachment_extractor(struct istream *input,
				     struct istream_attachment_settings *set,
				     void *context)
{
	struct attachment_istream *astream;

	i_assert(set->min_size > 0);
	i_assert(set->hash_format != NULL);
	i_assert(set->open_attachment_ostream != NULL);
	i_assert(set->close_attachment_ostream != NULL);

	astream = i_new(struct attachment_istream, 1);
	astream->part.temp_fd = -1;
	astream->set = *set;
	astream->context = context;
	astream->retry_read = TRUE;

	/* make sure the caller doesn't try to double-free this */
	set->hash_format = NULL;

	astream->istream.max_buffer_size = input->real_stream->max_buffer_size;

	astream->istream.read = i_stream_attachment_extractor_read;
	astream->istream.iostream.close = i_stream_attachment_extractor_close;

	astream->istream.istream.readable_fd = FALSE;
	astream->istream.istream.blocking = input->blocking;
	astream->istream.istream.seekable = FALSE;

	astream->pool = pool_alloconly_create("istream attachment", 1024);
	astream->parser = message_parser_init(astream->pool, input, 0,
				MESSAGE_PARSER_FLAG_INCLUDE_MULTIPART_BLOCKS |
				MESSAGE_PARSER_FLAG_INCLUDE_BOUNDARIES);
	return i_stream_create(&astream->istream, input,
			       i_stream_get_fd(input), 0);
}

bool i_stream_attachment_extractor_can_retry(struct istream *input)
{
	struct attachment_istream *astream =
		(struct attachment_istream *)input->real_stream;

	return astream->retry_read;
}
