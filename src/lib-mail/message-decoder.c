/* Copyright (c) 2006-2007 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "base64.h"
#include "str.h"
#include "unichar.h"
#include "charset-utf8.h"
#include "quoted-printable.h"
#include "rfc822-parser.h"
#include "message-parser.h"
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

	unsigned int dtcase:1;
	unsigned int charset_utf8:1;
};

struct message_decoder_context *message_decoder_init(bool dtcase)
{
	struct message_decoder_context *ctx;

	ctx = i_new(struct message_decoder_context, 1);
	ctx->dtcase = dtcase;
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

	buffer_free(&ctx->buf);
	buffer_free(&ctx->buf2);
	i_free(ctx->content_charset);
	i_free(ctx);
}

static void
parse_content_transfer_encoding(struct message_decoder_context *ctx,
				struct message_header_line *hdr)
{
	struct rfc822_parser_context parser;
	string_t *value;

	t_push();
	value = t_str_new(64);
	rfc822_parser_init(&parser, hdr->full_value, hdr->full_value_len, NULL);

	(void)rfc822_skip_lwsp(&parser);
	(void)rfc822_parse_mime_token(&parser, value);

	switch (str_len(value)) {
	case 4:
		if (i_memcasecmp(str_data(value), "7bit", 4) == 0 ||
		    i_memcasecmp(str_data(value), "8bit", 4) == 0)
			ctx->content_type = CONTENT_TYPE_BINARY;
		break;
	case 6:
		if (i_memcasecmp(str_data(value), "base64", 6) == 0)
			ctx->content_type = CONTENT_TYPE_BASE64;
		else if (i_memcasecmp(str_data(value), "binary", 6) == 0)
			ctx->content_type = CONTENT_TYPE_BINARY;
		break;
	case 16:
		if (i_memcasecmp(str_data(value), "quoted-printable", 16) == 0)
			ctx->content_type = CONTENT_TYPE_QP;
		break;
	}
	t_pop();
}

static void
parse_content_type(struct message_decoder_context *ctx,
		   struct message_header_line *hdr)
{
	struct rfc822_parser_context parser;
	const char *key, *value;
	string_t *str;

	if (ctx->content_charset != NULL)
		return;

	rfc822_parser_init(&parser, hdr->full_value, hdr->full_value_len, NULL);
	(void)rfc822_skip_lwsp(&parser);
	t_push();
	str = t_str_new(64);
	if (rfc822_parse_content_type(&parser, str) <= 0) {
		t_pop();
		return;
	}

	while (rfc822_parse_content_param(&parser, &key, &value) > 0) {
		if (strcasecmp(key, "charset") == 0) {
			ctx->content_charset = i_strdup(value);
			ctx->charset_utf8 = charset_is_utf8(value);
			break;
		}
	}
	t_pop();
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
	    strcasecmp(hdr->name, "Content-Type") == 0)
		parse_content_type(ctx, hdr);
	if (hdr->name_len == 25 &&
	    strcasecmp(hdr->name, "Content-Transfer-Encoding") == 0)
		parse_content_transfer_encoding(ctx, hdr);

	buffer_set_used_size(ctx->buf, 0);
	message_header_decode_utf8(hdr->full_value, hdr->full_value_len,
				   ctx->buf, ctx->dtcase);
	value_len = ctx->buf->used;

	if (ctx->dtcase) {
		(void)uni_utf8_to_decomposed_titlecase(hdr->name, hdr->name_len,
						       ctx->buf);
		buffer_append_c(ctx->buf, '\0');
	}

	ctx->hdr = *hdr;
	ctx->hdr.full_value = ctx->buf->data;
	ctx->hdr.full_value_len = value_len;
	ctx->hdr.value_len = 0;
	if (ctx->dtcase) {
		ctx->hdr.name = CONST_PTR_OFFSET(ctx->buf->data,
						 ctx->hdr.full_value_len);
		ctx->hdr.name_len = ctx->buf->used - 1 - value_len;
	}

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
	(void)charset_to_utf8(ctx->charset_trans, *data, &pos, ctx->buf2);

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
	int ret;

	if (ctx->charset_trans == NULL && !ctx->charset_utf8) {
		if (charset_to_utf8_begin(ctx->content_charset != NULL ?
					  ctx->content_charset : "UTF-8",
					  ctx->dtcase, &ctx->charset_trans) < 0)
			ctx->charset_trans = NULL;
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
		if (ctx->dtcase) {
			buffer_set_used_size(ctx->buf2, 0);
			(void)uni_utf8_to_decomposed_titlecase(data, size,
							       ctx->buf);
			output->data = ctx->buf2->data;
			output->size = ctx->buf2->used;
		} else {
			output->data = data;
			output->size = size;
		}
	} else if (ctx->charset_trans == NULL) {
		output->data = data;
		output->size = size;
	} else {
		buffer_set_used_size(ctx->buf2, 0);
		if (ctx->translation_size != 0)
			translation_buf_decode(ctx, &data, &size);

		pos = size;
		(void)charset_to_utf8(ctx->charset_trans,
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
