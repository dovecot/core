/* Copyright (C) 2002-2007 Timo Sirainen */

#include "lib.h"
#include "buffer.h"
#include "istream.h"
#include "str.h"
#include "str-find.h"
#include "charset-utf8.h"
#include "rfc822-parser.h"
#include "message-decoder.h"
#include "message-parser.h"
#include "message-search.h"

struct message_search_context {
	pool_t pool;

	char *key;
	char *key_charset;
	unsigned int key_len;

	enum message_search_flags flags;
	struct str_find_context *str_find_ctx;
	struct message_part *prev_part;

	struct message_decoder_context *decoder;
	unsigned int content_type_text:1; /* text/any or message/any */
};

int message_search_init(pool_t pool, const char *key, const char *charset,
			enum message_search_flags flags,
			struct message_search_context **ctx_r)
{
	struct message_search_context *ctx;
	struct charset_translation *t;
	string_t *key_utf8;
	size_t key_len;

	if (charset_to_utf8_begin(charset, TRUE, &t) < 0)
		return 0;

	t_push();
	key_utf8 = t_str_new(I_MAX(128, key_len*2));
	key_len = strlen(key);
	if (charset_to_utf8(t, (const unsigned char *)key, &key_len,
			    key_utf8) != CHARSET_RET_OK) {
		t_pop();
		return -1;
	}

	ctx = *ctx_r = p_new(pool, struct message_search_context, 1);
	ctx->pool = pool;
	ctx->key = p_strdup(pool, str_c(key_utf8));
	ctx->key_len = str_len(key_utf8);
	ctx->key_charset = p_strdup(pool, charset);
	ctx->flags = flags;
	ctx->decoder = message_decoder_init(TRUE);
	ctx->str_find_ctx = str_find_init(pool, ctx->key);
	t_pop();
	return 1;
}

void message_search_deinit(struct message_search_context **_ctx)
{
	struct message_search_context *ctx = *_ctx;

	*_ctx = NULL;
	str_find_deinit(&ctx->str_find_ctx);
	message_decoder_deinit(&ctx->decoder);
	p_free(ctx->pool, ctx->key);
	p_free(ctx->pool, ctx->key_charset);
	p_free(ctx->pool, ctx);
}

static void parse_content_type(struct message_search_context *ctx,
			       struct message_header_line *hdr)
{
	struct rfc822_parser_context parser;
	string_t *content_type;

	t_push();
	rfc822_parser_init(&parser, hdr->full_value, hdr->full_value_len, NULL);
	(void)rfc822_skip_lwsp(&parser);

	content_type = t_str_new(64);
	if (rfc822_parse_content_type(&parser, content_type) >= 0) {
		ctx->content_type_text =
			strncasecmp(str_c(content_type), "text/", 5) == 0 ||
			strncasecmp(str_c(content_type), "message/", 8) == 0;
	}
	t_pop();
}

static void handle_header(struct message_search_context *ctx,
			  struct message_header_line *hdr)
{
	if (hdr->name_len == 12 &&
	    strcasecmp(hdr->name, "Content-Type") == 0) {
		if (hdr->continues) {
			hdr->use_full_value = TRUE;
			return;
		}
		parse_content_type(ctx, hdr);
	}
}

static bool search_header(struct message_search_context *ctx,
			  const struct message_header_line *hdr)
{
	return str_find_more(ctx->str_find_ctx,
			     (const unsigned char *)hdr->name, hdr->name_len) ||
		str_find_more(ctx->str_find_ctx,
			      hdr->middle, hdr->middle_len) ||
		str_find_more(ctx->str_find_ctx, hdr->full_value,
			      hdr->full_value_len);
}

int message_search_more(struct message_search_context *ctx,
			struct message_block *raw_block)
{
	struct message_block block;

	if (raw_block->hdr != NULL) {
		if (ctx->flags & MESSAGE_SEARCH_FLAG_SKIP_HEADERS)
			return 0;

		handle_header(ctx, raw_block->hdr);
	} else {
		/* body */
		if (!ctx->content_type_text)
			return 0;
	}
	if (!message_decoder_decode_next_block(ctx->decoder, raw_block, &block))
		return 0;

	return message_search_more_decoded(ctx, &block);
}

int message_search_more_decoded(struct message_search_context *ctx,
				struct message_block *block)
{
	if (block->part != ctx->prev_part) {
		/* part changes */
		message_search_reset(ctx);
		ctx->prev_part = block->part;
	}

	if (block->hdr != NULL) {
		if (search_header(ctx, block->hdr))
			return 1;
	} else {
		if (str_find_more(ctx->str_find_ctx, block->data, block->size))
			return 1;
	}
	return 0;
}

void message_search_reset(struct message_search_context *ctx)
{
	/* Content-Type defaults to text/plain */
	ctx->content_type_text = TRUE;

	ctx->prev_part = NULL;
	str_find_reset(ctx->str_find_ctx);
}

int message_search_msg(struct message_search_context *ctx,
		       struct istream *input, const struct message_part *parts)
{
	const enum message_header_parser_flags hdr_parser_flags =
		MESSAGE_HEADER_PARSER_FLAG_CLEAN_ONELINE;
	struct message_parser_ctx *parser_ctx;
	struct message_block raw_block;
	int ret = 0;

	t_push();
	message_search_reset(ctx);

	if (parts != NULL) {
		parser_ctx = message_parser_init_from_parts(
						(struct message_part *)parts,
						input, hdr_parser_flags, 0);
	} else {
		parser_ctx = message_parser_init(pool_datastack_create(),
						 input, hdr_parser_flags, 0);
	}

	while ((ret = message_parser_parse_next_block(parser_ctx,
						      &raw_block)) > 0) {
		if ((ret = message_search_more(ctx, &raw_block)) != 0)
			break;
	}
	i_assert(ret != 0);
	if (ret < 0 && input->stream_errno == 0)
		ret = 0;
	(void)message_parser_deinit(&parser_ctx);
	t_pop();

	return ret;
}
