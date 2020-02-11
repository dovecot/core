/* Copyright (c) 2006-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "base64.h"
#include "str.h"
#include "unichar.h"
#include "charset-utf8.h"
#include "qp-decoder.h"
#include "rfc822-parser.h"
#include "rfc2231-parser.h"
#include "message-parser.h"
#include "message-header-decode.h"
#include "message-decoder.h"

struct message_decoder_context {
	enum message_decoder_flags flags;
	normalizer_func_t *normalizer;
	struct message_part *prev_part;

	struct message_header_line hdr;
	buffer_t *buf, *buf2;

	char *charset_trans_charset;
	struct charset_translation *charset_trans;
	char translation_buf[CHARSET_MAX_PENDING_BUF_SIZE];
	size_t translation_size;

	struct qp_decoder *qp;
	struct base64_decoder base64_decoder;

	char *content_type, *content_charset;
	enum message_cte message_cte;

	bool binary_input:1;
};

static void
message_decode_body_init_charset(struct message_decoder_context *ctx,
				 struct message_part *part);

struct message_decoder_context *
message_decoder_init(normalizer_func_t *normalizer,
		     enum message_decoder_flags flags)
{
	struct message_decoder_context *ctx;

	ctx = i_new(struct message_decoder_context, 1);
	ctx->flags = flags;
	ctx->normalizer = normalizer;
	ctx->buf = buffer_create_dynamic(default_pool, 8192);
	ctx->buf2 = buffer_create_dynamic(default_pool, 8192);
	base64_decode_init(&ctx->base64_decoder, &base64_scheme, 0);
	return ctx;
}

void message_decoder_deinit(struct message_decoder_context **_ctx)
{
	struct message_decoder_context *ctx = *_ctx;

	*_ctx = NULL;

	if (ctx->charset_trans != NULL)
		charset_to_utf8_end(&ctx->charset_trans);
	if (ctx->qp != NULL)
		qp_decoder_deinit(&ctx->qp);

	buffer_free(&ctx->buf);
	buffer_free(&ctx->buf2);
	i_free(ctx->charset_trans_charset);
	i_free(ctx->content_type);
	i_free(ctx->content_charset);
	i_free(ctx);
}

void message_decoder_set_return_binary(struct message_decoder_context *ctx,
				       bool set)
{
	if (set)
		ctx->flags |= MESSAGE_DECODER_FLAG_RETURN_BINARY;
	else
		ctx->flags &= ~MESSAGE_DECODER_FLAG_RETURN_BINARY;
	message_decode_body_init_charset(ctx, ctx->prev_part);
}

enum message_cte message_decoder_parse_cte(struct message_header_line *hdr)
{
	struct rfc822_parser_context parser;
	enum message_cte message_cte;
	string_t *value;

	value = t_str_new(64);
	rfc822_parser_init(&parser, hdr->full_value, hdr->full_value_len, NULL);

	rfc822_skip_lwsp(&parser);
	(void)rfc822_parse_mime_token(&parser, value);

	message_cte = MESSAGE_CTE_UNKNOWN;
	switch (str_len(value)) {
	case 4:
		if (i_memcasecmp(str_data(value), "7bit", 4) == 0 ||
		    i_memcasecmp(str_data(value), "8bit", 4) == 0)
			message_cte = MESSAGE_CTE_78BIT;
		break;
	case 6:
		if (i_memcasecmp(str_data(value), "base64", 6) == 0)
			message_cte = MESSAGE_CTE_BASE64;
		else if (i_memcasecmp(str_data(value), "binary", 6) == 0)
			message_cte = MESSAGE_CTE_BINARY;
		break;
	case 16:
		if (i_memcasecmp(str_data(value), "quoted-printable", 16) == 0)
			message_cte = MESSAGE_CTE_QP;
		break;
	}
	rfc822_parser_deinit(&parser);
	return message_cte;
}

static void
parse_content_type(struct message_decoder_context *ctx,
		   struct message_header_line *hdr)
{
	struct rfc822_parser_context parser;
	const char *const *results;
	string_t *str;
	int ret;

	if (ctx->content_type != NULL)
		return;

	rfc822_parser_init(&parser, hdr->full_value, hdr->full_value_len, NULL);
	rfc822_skip_lwsp(&parser);
	str = t_str_new(64);
	ret = rfc822_parse_content_type(&parser, str);
	ctx->content_type = i_strdup(str_c(str));
	if (ret < 0) {
		rfc822_parser_deinit(&parser);
		return;
	}

	rfc2231_parse(&parser, &results);
	for (; *results != NULL; results += 2) {
		if (strcasecmp(results[0], "charset") == 0) {
			ctx->content_charset = i_strdup(results[1]);
			break;
		}
	}
	rfc822_parser_deinit(&parser);
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

	T_BEGIN {
		if (hdr->name_len == 12 &&
		    strcasecmp(hdr->name, "Content-Type") == 0)
			parse_content_type(ctx, hdr);
		if (hdr->name_len == 25 &&
		    strcasecmp(hdr->name, "Content-Transfer-Encoding") == 0)
			ctx->message_cte = message_decoder_parse_cte(hdr);
	} T_END;

	buffer_set_used_size(ctx->buf, 0);
	message_header_decode_utf8(hdr->full_value, hdr->full_value_len,
				   ctx->buf, ctx->normalizer);
	value_len = ctx->buf->used;

	if (ctx->normalizer != NULL) {
		(void)ctx->normalizer(hdr->name, hdr->name_len, ctx->buf);
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
	unsigned char trans_buf[CHARSET_MAX_PENDING_BUF_SIZE+1];
	size_t data_wanted, skip;
	size_t trans_size, orig_size;

	/* @UNSAFE: move the previously untranslated bytes to trans_buf
	   and see if we have now enough data to get the next character
	   translated */
	memcpy(trans_buf, ctx->translation_buf, ctx->translation_size);
	data_wanted = sizeof(trans_buf) - ctx->translation_size;
	if (data_wanted > *size)
		data_wanted = *size;
	memcpy(trans_buf + ctx->translation_size, *data, data_wanted);

	orig_size = trans_size = ctx->translation_size + data_wanted;
	(void)charset_to_utf8(ctx->charset_trans, trans_buf,
			      &trans_size, ctx->buf2);

	if (trans_size <= ctx->translation_size) {
		/* need more data to finish the translation. */
		i_assert(orig_size < CHARSET_MAX_PENDING_BUF_SIZE);
		memcpy(ctx->translation_buf, trans_buf, orig_size);
		ctx->translation_size = orig_size;
		*data += *size;
		*size = 0;
		return;
	}
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
	ctx->binary_input = ctx->content_charset == NULL &&
		(ctx->flags & MESSAGE_DECODER_FLAG_RETURN_BINARY) != 0 &&
		(part->flags & (MESSAGE_PART_FLAG_TEXT |
				MESSAGE_PART_FLAG_MESSAGE_RFC822)) == 0;

	if (ctx->binary_input)
		return;

	if (ctx->charset_trans != NULL && ctx->content_charset != NULL &&
	    strcasecmp(ctx->content_charset, ctx->charset_trans_charset) == 0) {
		/* already have the correct translation selected */
		charset_to_utf8_reset(ctx->charset_trans);
		return;
	}

	if (ctx->charset_trans != NULL)
		charset_to_utf8_end(&ctx->charset_trans);
	i_free_and_null(ctx->charset_trans_charset);

	ctx->charset_trans_charset = i_strdup(ctx->content_charset != NULL ?
					      ctx->content_charset : "UTF-8");
	if (charset_to_utf8_begin(ctx->charset_trans_charset, ctx->normalizer,
				  &ctx->charset_trans) < 0)
		ctx->charset_trans = charset_utf8_to_utf8_begin(ctx->normalizer);
}

static bool message_decode_body(struct message_decoder_context *ctx,
				struct message_block *input,
				struct message_block *output)
{
	const unsigned char *data = NULL;
	size_t pos, size = 0;
	const char *error;

	switch (ctx->message_cte) {
	case MESSAGE_CTE_UNKNOWN:
		/* just skip this body */
		return FALSE;

	case MESSAGE_CTE_78BIT:
	case MESSAGE_CTE_BINARY:
		data = input->data;
		size = input->size;
		break;
	case MESSAGE_CTE_QP: {
		buffer_set_used_size(ctx->buf, 0);
		if (ctx->qp == NULL)
			ctx->qp = qp_decoder_init(ctx->buf);
		(void)qp_decoder_more(ctx->qp, input->data, input->size,
				      &pos, &error);
		data = ctx->buf->data;
		size = ctx->buf->used;
		break;
	}
	case MESSAGE_CTE_BASE64:
		buffer_set_used_size(ctx->buf, 0);
		if (!base64_decode_is_finished(&ctx->base64_decoder)) {
			if (base64_decode_more(&ctx->base64_decoder,
					       input->data, input->size,
					       &pos, ctx->buf) <= 0) {
				/* ignore the rest of the input in this
				   MIME part */
				(void)base64_decode_finish(&ctx->base64_decoder);
			}
		}
		data = ctx->buf->data;
		size = ctx->buf->used;
		break;
	}

	if (ctx->binary_input) {
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
		message_decoder_decode_reset(ctx);
	}

	output->part = input->part;
	ctx->prev_part = input->part;

	if (input->hdr != NULL) {
		output->size = 0;
		return message_decode_header(ctx, input->hdr, output);
	} else if (input->size != 0)
		return message_decode_body(ctx, input, output);
	else {
		output->hdr = NULL;
		output->size = 0;
		message_decode_body_init_charset(ctx, input->part);
		return TRUE;
	}
}

const char *
message_decoder_current_content_type(struct message_decoder_context *ctx)
{
	return ctx->content_type;
}

void message_decoder_decode_reset(struct message_decoder_context *ctx)
{
	const char *error;

	base64_decode_reset(&ctx->base64_decoder);

	if (ctx->qp != NULL)
		(void)qp_decoder_finish(ctx->qp, &error);
	i_free_and_null(ctx->content_type);
	i_free_and_null(ctx->content_charset);
	ctx->message_cte = MESSAGE_CTE_78BIT;
}
