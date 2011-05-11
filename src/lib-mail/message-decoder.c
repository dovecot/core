/* Copyright (c) 2006-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "base64.h"
#include "str.h"
#include "unichar.h"
#include "charset-utf8.h"
#include "quoted-printable.h"
#include "rfc822-parser.h"
#include "rfc2231-parser.h"
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
	enum message_decoder_flags flags;
	struct message_part *prev_part;

	struct message_header_line hdr;
	buffer_t *buf, *buf2;

	char *charset_trans_charset;
	struct charset_translation *charset_trans;
	char translation_buf[MAX_TRANSLATION_BUF_SIZE];
	unsigned int translation_size;

	buffer_t *encoding_buf;

	char *content_charset;
	enum content_type content_type;

	unsigned int charset_utf8:1;
	unsigned int binary_input:1;
};

struct message_decoder_context *
message_decoder_init(enum message_decoder_flags flags)
{
	struct message_decoder_context *ctx;

	ctx = i_new(struct message_decoder_context, 1);
	ctx->flags = flags;
	ctx->buf = buffer_create_dynamic(default_pool, 8192);
	ctx->buf2 = buffer_create_dynamic(default_pool, 8192);
	ctx->encoding_buf = buffer_create_dynamic(default_pool, 128);
	return ctx;
}

void message_decoder_deinit(struct message_decoder_context **_ctx)
{
	struct message_decoder_context *ctx = *_ctx;

	*_ctx = NULL;

	if (ctx->charset_trans != NULL)
		charset_to_utf8_end(&ctx->charset_trans);

	buffer_free(&ctx->encoding_buf);
	buffer_free(&ctx->buf);
	buffer_free(&ctx->buf2);
	i_free(ctx->charset_trans_charset);
	i_free(ctx->content_charset);
	i_free(ctx);
}

static void
parse_content_transfer_encoding(struct message_decoder_context *ctx,
				struct message_header_line *hdr)
{
	struct rfc822_parser_context parser;
	string_t *value;

	value = t_str_new(64);
	rfc822_parser_init(&parser, hdr->full_value, hdr->full_value_len, NULL);

	(void)rfc822_skip_lwsp(&parser);
	(void)rfc822_parse_mime_token(&parser, value);

	ctx->content_type = CONTENT_TYPE_UNKNOWN;
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
}

static void
parse_content_type(struct message_decoder_context *ctx,
		   struct message_header_line *hdr)
{
	struct rfc822_parser_context parser;
	const char *const *results;
	string_t *str;

	if (ctx->content_charset != NULL)
		return;

	rfc822_parser_init(&parser, hdr->full_value, hdr->full_value_len, NULL);
	(void)rfc822_skip_lwsp(&parser);
	str = t_str_new(64);
	if (rfc822_parse_content_type(&parser, str) <= 0)
		return;

	(void)rfc2231_parse(&parser, &results);
	for (; *results != NULL; results += 2) {
		if (strcasecmp(results[0], "charset") == 0) {
			ctx->content_charset = i_strdup(results[1]);
			ctx->charset_utf8 = charset_is_utf8(results[1]);
			break;
		}
	}
}

static bool message_decode_header(struct message_decoder_context *ctx,
				  struct message_header_line *hdr,
				  struct message_block *output)
{
	bool dtcase = (ctx->flags & MESSAGE_DECODER_FLAG_DTCASE) != 0;
	size_t value_len;

	if (hdr->continues) {
		hdr->use_full_value = TRUE;
		return FALSE;
	}

	T_BEGIN {
		if (hdr->name_len == 12 &&
		    strcasecmp(hdr->name, "Content-Type") == 0)
			parse_content_type(ctx, hdr);
		if (hdr->name_len == 25 &&
		    strcasecmp(hdr->name, "Content-Transfer-Encoding") == 0)
			parse_content_transfer_encoding(ctx, hdr);
	} T_END;

	buffer_set_used_size(ctx->buf, 0);
	message_header_decode_utf8(hdr->full_value, hdr->full_value_len,
				   ctx->buf, dtcase);
	value_len = ctx->buf->used;

	if (dtcase) {
		(void)uni_utf8_to_decomposed_titlecase(hdr->name, hdr->name_len,
						       ctx->buf);
		buffer_append_c(ctx->buf, '\0');
	} else {
		if (!uni_utf8_get_valid_data((const unsigned char *)hdr->name,
					     hdr->name_len, ctx->buf))
			buffer_append_c(ctx->buf, '\0');
	}

	ctx->hdr = *hdr;
	ctx->hdr.full_value = ctx->buf->data;
	ctx->hdr.full_value_len = value_len;
	ctx->hdr.value_len = 0;
	if (ctx->buf->used != value_len) {
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
	unsigned int data_wanted, skip;
	size_t trans_size;

	/* @UNSAFE: move the previously untranslated bytes to trans_buf
	   and see if we have now enough data to get the next character
	   translated */
	memcpy(trans_buf, ctx->translation_buf, ctx->translation_size);
	data_wanted = sizeof(trans_buf) - ctx->translation_size;
	if (data_wanted > *size)
		data_wanted = *size;
	memcpy(trans_buf + ctx->translation_size, *data, data_wanted);

	trans_size = ctx->translation_size + data_wanted;
	(void)charset_to_utf8(ctx->charset_trans, trans_buf,
			      &trans_size, ctx->buf2);

	i_assert(trans_size > ctx->translation_size);
	skip = trans_size - ctx->translation_size;

	i_assert(*size >= skip);
	*data += skip;
	*size -= skip;

	ctx->translation_size = 0;
}

static void
message_decode_body_init_charset(struct message_decoder_context *ctx,
				 struct message_part *part)
{
	enum charset_flags flags;

	ctx->binary_input = ctx->content_charset == NULL &&
		(ctx->flags & MESSAGE_DECODER_FLAG_RETURN_BINARY) != 0 &&
		(part->flags & (MESSAGE_PART_FLAG_TEXT |
				MESSAGE_PART_FLAG_MESSAGE_RFC822)) == 0;

	if (ctx->charset_utf8 || ctx->binary_input)
		return;

	if (ctx->charset_trans != NULL && ctx->content_charset != NULL &&
	    strcasecmp(ctx->content_charset, ctx->charset_trans_charset) == 0) {
		/* already have the correct translation selected */
		return;
	}

	if (ctx->charset_trans != NULL)
		charset_to_utf8_end(&ctx->charset_trans);
	i_free_and_null(ctx->charset_trans_charset);

	flags = (ctx->flags & MESSAGE_DECODER_FLAG_DTCASE) != 0 ?
		CHARSET_FLAG_DECOMP_TITLECASE : 0;
	ctx->charset_trans_charset = i_strdup(ctx->content_charset != NULL ?
					      ctx->content_charset : "UTF-8");
	if (charset_to_utf8_begin(ctx->charset_trans_charset,
				  flags, &ctx->charset_trans) < 0)
		ctx->charset_trans = NULL;
}

static bool message_decode_body(struct message_decoder_context *ctx,
				struct message_block *input,
				struct message_block *output)
{
	const unsigned char *data = NULL;
	size_t pos = 0, size = 0;
	int ret;

	if (ctx->encoding_buf->used != 0) {
		/* @UNSAFE */
		buffer_append(ctx->encoding_buf, input->data, input->size);
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
		if (ctx->encoding_buf->used != 0) {
			quoted_printable_decode(ctx->encoding_buf->data,
						ctx->encoding_buf->used,
						&pos, ctx->buf);
		} else {
			quoted_printable_decode(input->data, input->size,
						&pos, ctx->buf);
		}
		data = ctx->buf->data;
		size = ctx->buf->used;
		break;
	case CONTENT_TYPE_BASE64:
		buffer_set_used_size(ctx->buf, 0);
		if (ctx->encoding_buf->used != 0) {
			ret = base64_decode(ctx->encoding_buf->data,
					    ctx->encoding_buf->used,
					    &pos, ctx->buf);
		} else {
			ret = base64_decode(input->data, input->size,
					    &pos, ctx->buf);
		}
		if (ret < 0) {
			/* corrupted base64 data, don't bother with
			   the rest of it */
			return FALSE;
		}
		if (ret == 0) {
			/* end of base64 input */
			pos = input->size;
			buffer_set_used_size(ctx->encoding_buf, 0);
		}
		data = ctx->buf->data;
		size = ctx->buf->used;
		break;
	}

	if (ctx->encoding_buf->used != 0)
		buffer_delete(ctx->encoding_buf, 0, pos);
	else if (pos != input->size) {
		buffer_append(ctx->encoding_buf,
			      input->data + pos, input->size - pos);
	}

	if (ctx->binary_input) {
		output->data = data;
		output->size = size;
	} else if (ctx->charset_utf8) {
		buffer_set_used_size(ctx->buf2, 0);
		if ((ctx->flags & MESSAGE_DECODER_FLAG_DTCASE) != 0) {
			(void)uni_utf8_to_decomposed_titlecase(data, size,
							       ctx->buf2);
			output->data = ctx->buf2->data;
			output->size = ctx->buf2->used;
		} else if (uni_utf8_get_valid_data(data, size, ctx->buf2)) {
			output->data = data;
			output->size = size;
		} else {
			output->data = ctx->buf2->data;
			output->size = ctx->buf2->used;
		}
	} else if (ctx->charset_trans == NULL) {
		/* unknown charset */
		buffer_set_used_size(ctx->buf2, 0);
		if (uni_utf8_get_valid_data(data, size, ctx->buf2)) {
			output->data = data;
			output->size = size;
		} else {
			output->data = ctx->buf2->data;
			output->size = ctx->buf2->used;
		}
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
		message_decoder_decode_reset(ctx);
	}

	output->part = input->part;
	ctx->prev_part = input->part;

	if (input->hdr != NULL)
		return message_decode_header(ctx, input->hdr, output);
	else if (input->size != 0)
		return message_decode_body(ctx, input, output);
	else {
		output->hdr = NULL;
		output->size = 0;
		message_decode_body_init_charset(ctx, input->part);
		return TRUE;
	}
}

void message_decoder_decode_reset(struct message_decoder_context *ctx)
{
	i_free_and_null(ctx->content_charset);
	ctx->content_type = CONTENT_TYPE_BINARY;
	ctx->charset_utf8 = TRUE;
	buffer_set_used_size(ctx->encoding_buf, 0);
}
