/* Copyright (C) 2002-2007 Timo Sirainen */

#include "lib.h"
#include "buffer.h"
#include "istream.h"
#include "str-find.h"
#include "charset-utf8.h"
#include "message-decoder.h"
#include "message-parser.h"
#include "message-content-parser.h"
#include "message-body-search.h"

struct message_body_search_context {
	pool_t pool;

	char *key;
	char *key_charset;
	unsigned int key_len;

	struct str_find_context *str_find_ctx;

	struct message_decoder_context *decoder;
	unsigned int search_header:1;
	unsigned int content_type_text:1; /* text/any or message/any */
};

static void parse_content_type(const unsigned char *value, size_t value_len,
			       void *context)
{
	struct message_body_search_context *ctx = context;
	const char *str;

	t_push();
	str = t_strndup(value, value_len);
	ctx->content_type_text =
		strncasecmp(str, "text/", 5) == 0 ||
		strncasecmp(str, "message/", 8) == 0;
	t_pop();
}

int message_body_search_init(pool_t pool, const char *key, const char *charset,
			     bool search_header,
			     struct message_body_search_context **ctx_r)
{
	struct message_body_search_context *ctx;
	bool unknown_charset;
	size_t key_len;

	/* get the key uppercased */
	t_push();
	key = charset_to_ucase_utf8_string(charset, &unknown_charset,
					   (const unsigned char *)key,
					   strlen(key), &key_len);
	if (key == NULL) {
		t_pop();
		return unknown_charset ? 0 : -1;
	}

	ctx = *ctx_r = p_new(pool, struct message_body_search_context, 1);
	ctx->pool = pool;
	ctx->key = p_strdup(pool, key);
	ctx->key_len = key_len;
	ctx->key_charset = p_strdup(pool, charset);
	ctx->search_header = search_header;
	ctx->decoder = message_decoder_init_ucase();
	ctx->str_find_ctx = str_find_init(pool, ctx->key);
	t_pop();
	return 1;
}

void message_body_search_deinit(struct message_body_search_context **_ctx)
{
	struct message_body_search_context *ctx = *_ctx;

	*_ctx = NULL;
	str_find_deinit(&ctx->str_find_ctx);
	message_decoder_deinit(&ctx->decoder);
	p_free(ctx->pool, ctx->key);
	p_free(ctx->pool, ctx->key_charset);
	p_free(ctx->pool, ctx);
}

static void handle_header(struct message_body_search_context *ctx,
			  struct message_header_line *hdr)
{
	if (hdr->name_len == 12 &&
	    strcasecmp(hdr->name, "Content-Type") == 0) {
		if (hdr->continues) {
			hdr->use_full_value = TRUE;
			return;
		}
		message_content_parse_header(hdr->full_value,
					     hdr->full_value_len,
					     parse_content_type, NULL, ctx);
	}
}

static bool search_header(struct message_body_search_context *ctx,
			  const struct message_header_line *hdr)
{
	return str_find_more(ctx->str_find_ctx,
			     (const unsigned char *)hdr->name, hdr->name_len) ||
		str_find_more(ctx->str_find_ctx,
			      hdr->middle, hdr->middle_len) ||
		str_find_more(ctx->str_find_ctx, hdr->full_value,
			      hdr->full_value_len);
}

int message_body_search(struct message_body_search_context *ctx,
			struct istream *input,
			const struct message_part *parts)
{
	const enum message_header_parser_flags hdr_parser_flags =
		MESSAGE_HEADER_PARSER_FLAG_CLEAN_ONELINE;
	struct message_parser_ctx *parser_ctx;
	struct message_block raw_block, block;
	int ret = 0;

	t_push();
	/* Content-Type defaults to text/plain */
	ctx->content_type_text = TRUE;

	parser_ctx =
		message_parser_init_from_parts((struct message_part *)parts,
					       input, hdr_parser_flags, 0);

	while ((ret = message_parser_parse_next_block(parser_ctx,
						      &raw_block)) > 0) {
		if (raw_block.hdr != NULL) {
			if (raw_block.part->parent == NULL &&
			    !ctx->search_header) {
				/* skipping the main header */
				continue;
			}

			handle_header(ctx, raw_block.hdr);
		} else if (raw_block.size == 0) {
			/* part changes */
			ctx->content_type_text = TRUE;
			str_find_reset(ctx->str_find_ctx);
			continue;
		} else {
			/* body */
			if (!ctx->content_type_text)
				continue;
		}
		if (!message_decoder_decode_next_block(ctx->decoder, &raw_block,
						       &block))
			continue;

		if (block.hdr != NULL) {
			if (search_header(ctx, block.hdr)) {
				ret = 1;
				break;
			}
		} else {
			if (str_find_more(ctx->str_find_ctx,
					  block.data, block.size)) {
				ret = 1;
				break;
			}
		}
	}
	i_assert(ret != 0);
	if (ret < 0 && input->stream_errno == 0)
		ret = 0;
	(void)message_parser_deinit(&parser_ctx);
	t_pop();

	return ret;
}
