/* Copyright (C) 2006 Timo Sirainen */

#include "lib.h"
#include "buffer.h"
#include "strescape.h"
#include "base64.h"
#include "charset-utf8.h"
#include "quoted-printable.h"
#include "message-parser.h"
#include "message-content-parser.h"
#include "message-header-decode.h"
#include "message-decoder.h"

enum content_type {
	CONTENT_TYPE_UNKNOWN = 0,
	CONTENT_TYPE_BINARY,
	CONTENT_TYPE_QP,
	CONTENT_TYPE_BASE64
};

/* base64 takes max 4 bytes per character, q-p takes max 3. */
#define MAX_ENCODING_BUF_SIZE 3

/* UTF-8 takes max 5 bytes per character. Not sure about others, but I'd think
   10 is more than enough for everyone.. */
#define MAX_TRANSLATION_BUF_SIZE 10

struct message_decoder_context {
	struct message_part *prev_part;

	struct message_header_line hdr;
	buffer_t *buf, *buf2;

	struct charset_translation *charset_trans;
	char translation_buf[MAX_TRANSLATION_BUF_SIZE];
	unsigned int translation_size;

	char encoding_buf[MAX_ENCODING_BUF_SIZE];
	unsigned int encoding_size;

	char *content_charset;
	enum content_type content_type;

	unsigned int charset_utf8:1;
};

struct message_decoder_context *message_decoder_init_ucase(void)
{
	struct message_decoder_context *ctx;

	ctx = i_new(struct message_decoder_context, 1);
	ctx->buf = buffer_create_dynamic(default_pool, 8192);
	ctx->buf2 = buffer_create_dynamic(default_pool, 8192);
	return ctx;
}

void message_decoder_deinit(struct message_decoder_context **_ctx)
{
	struct message_decoder_context *ctx = *_ctx;

	*_ctx = NULL;

	if (ctx->charset_trans != NULL)
		charset_to_utf8_end(&ctx->charset_trans);

	buffer_free(ctx->buf);
	buffer_free(ctx->buf2);
	i_free(ctx->content_charset);
	i_free(ctx);
}

static bool
message_decode_header_callback(const unsigned char *data, size_t size,
			       const char *charset, void *context)
{
	struct message_decoder_context *ctx = context;
	struct charset_translation *t;
	bool unknown_charset;

	if (charset == NULL || charset_is_utf8(charset)) {
		/* ASCII */
		_charset_utf8_ucase(data, size, ctx->buf, ctx->buf->used);
		return TRUE;
	}

	t = charset_to_utf8_begin(charset, &unknown_charset);
	if (unknown_charset) {
		/* let's just ignore this part */
		return TRUE;
	}

	/* ignore any errors */
	(void)charset_to_ucase_utf8_full(t, data, &size, ctx->buf);
	charset_to_utf8_end(&t);
	return TRUE;
}

static void parse_content_encoding(const unsigned char *value, size_t value_len,
				   void *context)
{
	struct message_decoder_context *ctx = context;

	ctx->content_type = CONTENT_TYPE_UNKNOWN;

	switch (value_len) {
	case 4:
		if (memcasecmp(value, "7bit", 4) == 0 ||
		    memcasecmp(value, "8bit", 4) == 0)
			ctx->content_type = CONTENT_TYPE_BINARY;
		break;
	case 6:
		if (memcasecmp(value, "base64", 6) == 0)
			ctx->content_type = CONTENT_TYPE_BASE64;
		else if (memcasecmp(value, "binary", 6) == 0)
			ctx->content_type = CONTENT_TYPE_BINARY;
		break;
	case 16:
		if (memcasecmp(value, "quoted-printable", 16) == 0)
			ctx->content_type = CONTENT_TYPE_QP;
		break;
	}
}

static void
parse_content_type_param(const unsigned char *name, size_t name_len,
			 const unsigned char *value, size_t value_len,
			 bool value_quoted, void *context)
{
	struct message_decoder_context *ctx = context;

	if (name_len == 7 && memcasecmp(name, "charset", 7) == 0 &&
	    ctx->content_charset == NULL) {
		ctx->content_charset = i_strndup(value, value_len);
		if (value_quoted) str_unescape(ctx->content_charset);

		ctx->charset_utf8 = charset_is_utf8(ctx->content_charset);
	}
}

static bool message_decode_header(struct message_decoder_context *ctx,
				  struct message_header_line *hdr,
				  struct message_block *output)
{
	size_t value_len;

	if (hdr->continues) {
		hdr->use_full_value = TRUE;
		return FALSE;
	}

	if (hdr->name_len == 12 &&
	    strcasecmp(hdr->name, "Content-Type") == 0) {
		message_content_parse_header(hdr->full_value,
					     hdr->full_value_len,
					     null_parse_content_callback,
					     parse_content_type_param, ctx);
	}
	if (hdr->name_len == 25 &&
	    strcasecmp(hdr->name, "Content-Transfer-Encoding") == 0) {
		message_content_parse_header(hdr->full_value,
					     hdr->full_value_len,
					     parse_content_encoding,
					     null_parse_content_param_callback,
					     ctx);
	}

	buffer_set_used_size(ctx->buf, 0);
	message_header_decode(hdr->full_value, hdr->full_value_len,
			      message_decode_header_callback, ctx);
	value_len = ctx->buf->used;

	_charset_utf8_ucase((const unsigned char *)hdr->name, hdr->name_len,
			    ctx->buf, ctx->buf->used);
	buffer_append_c(ctx->buf, '\0');

	ctx->hdr = *hdr;
	ctx->hdr.full_value = ctx->buf->data;
	ctx->hdr.full_value_len = value_len;
	ctx->hdr.value_len = 0;
	ctx->hdr.name = CONST_PTR_OFFSET(ctx->buf->data,
					 ctx->hdr.full_value_len);
	ctx->hdr.name_len = ctx->buf->used - 1 - value_len;

	output->hdr = &ctx->hdr;
	return TRUE;
}

static void translation_buf_decode(struct message_decoder_context *ctx,
				   const unsigned char **data, size_t *size)
{
	unsigned char trans_buf[MAX_TRANSLATION_BUF_SIZE+1];
	size_t pos, skip;

	/* @UNSAFE */
	memcpy(trans_buf, ctx->translation_buf, ctx->translation_size);
	skip = sizeof(trans_buf) - ctx->translation_size;
	if (skip > *size)
		skip = *size;
	memcpy(trans_buf + ctx->translation_size, data, skip);

	pos = *size;
	(void)charset_to_ucase_utf8_full(ctx->charset_trans,
					 *data, &pos, ctx->buf2);

	i_assert(pos > ctx->translation_size);
	skip = (ctx->translation_size + skip) - pos;

	i_assert(*size >= skip);
	*data += skip;
	*size -= skip;

	ctx->translation_size = 0;
}

static bool message_decode_body(struct message_decoder_context *ctx,
				struct message_block *input,
				struct message_block *output)
{
	unsigned char new_buf[MAX_ENCODING_BUF_SIZE+1];
	const unsigned char *data = NULL;
	size_t pos, size = 0, skip = 0;
	bool unknown_charset;
	int ret;

	if (ctx->charset_trans == NULL && !ctx->charset_utf8) {
		ctx->charset_trans =
			charset_to_utf8_begin(ctx->content_charset != NULL ?
					      ctx->content_charset : "UTF-8",
					      &unknown_charset);
	}

	if (ctx->encoding_size != 0) {
		/* @UNSAFE */
		memcpy(new_buf, ctx->encoding_buf, ctx->encoding_size);
		skip = sizeof(new_buf) - ctx->encoding_size;
		if (skip > input->size)
			skip = input->size;
		memcpy(new_buf + ctx->encoding_size, input->data, skip);
	}

	switch (ctx->content_type) {
	case CONTENT_TYPE_UNKNOWN:
		/* just skip this body */
		return FALSE;

	case CONTENT_TYPE_BINARY:
		data = input->data;
		size = pos = input->size;
		break;
	case CONTENT_TYPE_QP:
		buffer_set_used_size(ctx->buf, 0);
		if (ctx->encoding_size != 0) {
			quoted_printable_decode(new_buf,
						ctx->encoding_size + skip,
						&pos, ctx->buf);
			i_assert(pos >= ctx->encoding_size);
			skip = pos - ctx->encoding_size;
		}

		quoted_printable_decode(input->data + skip, input->size - skip,
					&pos, ctx->buf);
		pos += skip;
		data = ctx->buf->data;
		size = ctx->buf->used;
		break;
	case CONTENT_TYPE_BASE64:
		buffer_set_used_size(ctx->buf, 0);
		if (ctx->encoding_size != 0) {
			if (base64_decode(new_buf, ctx->encoding_size + skip,
					  &pos, ctx->buf) < 0) {
				/* corrupted base64 data, don't bother with
				   the rest of it */
				return FALSE;
			}
			i_assert(pos >= ctx->encoding_size);
			skip = pos - ctx->encoding_size;
		}
		ret = base64_decode(input->data + skip, input->size - skip,
				    &pos, ctx->buf);
		if (ret < 0) {
			/* corrupted base64 data, don't bother with
			   the rest of it */
			return FALSE;
		}
		if (ret == 0) {
			/* end of base64 input */
			pos = input->size - skip;
		}
		pos += skip;
		data = ctx->buf->data;
		size = ctx->buf->used;
		break;
	}

	if (pos != input->size) {
		/* @UNSAFE */
		i_assert(pos < input->size);
		ctx->encoding_size = input->size - pos;
		i_assert(ctx->encoding_size <= sizeof(ctx->encoding_buf));
		memcpy(ctx->encoding_buf, input->data + pos,
		       ctx->encoding_size);
	} else {
		ctx->encoding_size = 0;
	}

	if (ctx->charset_utf8) {
#if 0
		buffer_set_used_size(ctx->buf2, 0);
		_charset_utf8_ucase(data, size, ctx->buf2, ctx->buf2->used);
		output->data = ctx->buf2->data;
		output->size = ctx->buf2->used;
	} else if (ctx->charset_trans == NULL) {
#endif
		output->data = data;
		output->size = size;
	} else {
		buffer_set_used_size(ctx->buf2, 0);
		if (ctx->translation_size != 0)
			translation_buf_decode(ctx, &data, &size);

		pos = size;
		(void)charset_to_ucase_utf8_full(ctx->charset_trans,
						 data, &pos, ctx->buf2);
		if (pos != size) {
			ctx->translation_size = size - pos;
			i_assert(ctx->translation_size <=
				 sizeof(ctx->translation_buf));
			memcpy(ctx->translation_buf, data + pos,
			       ctx->translation_size);
		}
		output->data = ctx->buf2->data;
		output->size = ctx->buf2->used;
	}

	output->hdr = NULL;
	return TRUE;
}

bool message_decoder_decode_next_block(struct message_decoder_context *ctx,
				       struct message_block *input,
				       struct message_block *output)
{
	if (input->part != ctx->prev_part) {
		/* MIME part changed. */
		i_free_and_null(ctx->content_charset);
		ctx->content_type = CONTENT_TYPE_BINARY;
		ctx->charset_utf8 = TRUE;
		ctx->encoding_size = 0;
	}

	output->part = input->part;
	ctx->prev_part = input->part;

	if (input->hdr != NULL)
		return message_decode_header(ctx, input->hdr, output);
	else
		return message_decode_body(ctx, input, output);
}
