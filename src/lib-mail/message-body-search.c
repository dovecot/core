/* Copyright (C) 2002-2007 Timo Sirainen */

#include "lib.h"
#include "buffer.h"
#include "istream.h"
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

	struct message_decoder_context *decoder;
	unsigned int search_header:1;
};

struct part_search_context {
	struct message_body_search_context *body_ctx;

	buffer_t *match_buf;

	unsigned int content_type_text:1; /* text/any or message/any */
};

static void parse_content_type(const unsigned char *value, size_t value_len,
			       void *context)
{
	struct part_search_context *ctx = context;
	const char *str;

	t_push();
	str = t_strndup(value, value_len);
	ctx->content_type_text =
		strncasecmp(str, "text/", 5) == 0 ||
		strncasecmp(str, "message/", 8) == 0;
	t_pop();
}

static bool
message_search_decoded_block(struct part_search_context *ctx,
			     const unsigned char *data, size_t size)
{
	const unsigned char *p, *end, *key;
	unsigned int key_len;
	size_t *matches, match_count, value;
	ssize_t i;

	key = (const unsigned char *) ctx->body_ctx->key;
	key_len = ctx->body_ctx->key_len;

	matches = buffer_get_modifiable_data(ctx->match_buf, &match_count);
	match_count /= sizeof(size_t);

	end = data + size;
	for (p = data; p != end; p++) {
		for (i = match_count-1; i >= 0; i--) {
			if (key[matches[i]] == *p) {
				if (++matches[i] == key_len) {
					/* full match */
					p++;
					return TRUE;
				}
			} else {
				/* non-match */
				buffer_delete(ctx->match_buf,
					      i * sizeof(size_t),
					      sizeof(size_t));
				match_count--;
			}
		}

		if (*p == key[0]) {
			if (key_len == 1) {
				/* only one character in search key */
				p++;
				return TRUE;
			}

			value = 1;
			buffer_append(ctx->match_buf, &value, sizeof(value));
			match_count++;
		}
	}

	return FALSE;
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

	t_pop();
	return 1;
}

void message_body_search_deinit(struct message_body_search_context **_ctx)
{
	struct message_body_search_context *ctx = *_ctx;

	*_ctx = NULL;
	message_decoder_deinit(&ctx->decoder);
	p_free(ctx->pool, ctx->key);
	p_free(ctx->pool, ctx->key_charset);
	p_free(ctx->pool, ctx);
}

static void handle_header(struct part_search_context *ctx,
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

static bool search_header(struct part_search_context *ctx,
			  const struct message_header_line *hdr)
{
	return message_search_decoded_block(ctx,
					    (const unsigned char *)hdr->name,
					    hdr->name_len) ||
		message_search_decoded_block(ctx, hdr->middle,
					     hdr->middle_len) ||
		message_search_decoded_block(ctx, hdr->full_value,
					     hdr->full_value_len);
}

int message_body_search(struct message_body_search_context *ctx,
			struct istream *input,
			const struct message_part *parts)
{
	struct message_parser_ctx *parser_ctx;
	struct part_search_context part_ctx;
	struct message_block raw_block, block;
	int ret = 0;

	t_push();
	/* Content-Type defaults to text/plain */
	memset(&part_ctx, 0, sizeof(part_ctx));
	part_ctx.body_ctx = ctx;
	part_ctx.content_type_text = TRUE;
	part_ctx.match_buf =
		buffer_create_static_hard(pool_datastack_create(),
					  sizeof(size_t) * ctx->key_len);

	parser_ctx =
		message_parser_init_from_parts((struct message_part *)parts,
					       input, TRUE);

	while ((ret = message_parser_parse_next_block(parser_ctx,
						      &raw_block)) > 0) {
		if (raw_block.hdr != NULL) {
			if (raw_block.part->parent == NULL &&
			    !ctx->search_header) {
				/* skipping the main header */
				continue;
			}

			handle_header(&part_ctx, raw_block.hdr);
		} else if (raw_block.size == 0) {
			/* part changes */
			part_ctx.content_type_text = TRUE;
			buffer_reset(part_ctx.match_buf);
			continue;
		} else {
			/* body */
			if (!part_ctx.content_type_text)
				continue;
		}
		if (!message_decoder_decode_next_block(ctx->decoder, &raw_block,
						       &block))
			continue;

		if (block.hdr != NULL) {
			if (search_header(&part_ctx, block.hdr)) {
				ret = 1;
				break;
			}
		} else {
			if (message_search_decoded_block(&part_ctx, block.data,
							 block.size)) {
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
