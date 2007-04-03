/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "base64.h"
#include "buffer.h"
#include "charset-utf8.h"
#include "quoted-printable.h"
#include "message-parser.h"
#include "message-header-decode.h"
#include "message-header-search.h"

#include <ctype.h>

struct message_header_search_context {
	pool_t pool;

	unsigned char *key;
	size_t key_len;
	char *key_charset;

	buffer_t *match_buf;

	unsigned int found:1;
	unsigned int last_newline:1;
	unsigned int unknown_charset:1;
};

int message_header_search_init(pool_t pool, const char *key,
			       const char *charset,
			       struct message_header_search_context **ctx_r)
{
	struct message_header_search_context *ctx;
	size_t key_len;
	bool unknown_charset;

	/* get the key uppercased */
	t_push();
	key = charset_to_ucase_utf8_string(charset, &unknown_charset,
					   (const unsigned char *) key,
					   strlen(key), &key_len);

	if (key == NULL) {
		t_pop();
		return unknown_charset ? 0 : -1;
	}

	ctx = *ctx_r = p_new(pool, struct message_header_search_context, 1);
	ctx->pool = pool;
	ctx->key = (unsigned char *) p_strdup(pool, key);
	ctx->key_len = key_len;
	ctx->key_charset = p_strdup(pool, charset);
	ctx->unknown_charset = charset == NULL;

	i_assert(ctx->key_len <= SSIZE_T_MAX/sizeof(size_t));
	ctx->match_buf = buffer_create_static_hard(pool, sizeof(size_t) *
						   ctx->key_len);
	t_pop();
	return 1;
}

void message_header_search_deinit(struct message_header_search_context **_ctx)
{
        struct message_header_search_context *ctx = *_ctx;
	pool_t pool;

	*_ctx = NULL;

	buffer_free(ctx->match_buf);

	pool = ctx->pool;
	p_free(pool, ctx->key);
	p_free(pool, ctx->key_charset);
	p_free(pool, ctx);
}

static void search_loop(struct message_header_search_context *ctx,
			const unsigned char *data, size_t size)
{
	size_t pos, *matches, match_count, value;
	ssize_t i;
	unsigned char chr;
	bool last_newline;

	matches = buffer_get_modifiable_data(ctx->match_buf, &match_count);
	match_count /= sizeof(size_t);

	last_newline = ctx->last_newline;
	for (pos = 0; pos < size; pos++) {
		chr = data[pos];

		if (last_newline) {
			if (!IS_LWSP(chr)) {
				/* not a long header, reset matches */
				buffer_set_used_size(ctx->match_buf, 0);
				match_count = 0;
			}
			chr = ' ';
		}
		last_newline = chr == '\n';

		if (chr == '\r' || chr == '\n')
			continue;

		for (i = match_count-1; i >= 0; i--) {
			if (ctx->key[matches[i]] == chr) {
				if (++matches[i] == ctx->key_len) {
					/* full match */
					ctx->found = TRUE;
					return;
				}
			} else {
				/* non-match */
				buffer_delete(ctx->match_buf,
					      i * sizeof(size_t),
					      sizeof(size_t));
				match_count--;
			}
		}

		if (chr == ctx->key[0]) {
			if (ctx->key_len == 1) {
				/* only one character in search key */
				ctx->found = TRUE;
				break;
			}

			value = 1;
			buffer_append(ctx->match_buf, &value, sizeof(value));
			match_count++;
		}
	}

	ctx->last_newline = last_newline;
}

static void search_with_charset(const unsigned char *data, size_t size,
				const char *charset,
				struct message_header_search_context *ctx)
{
	const void *utf8_data;
	size_t utf8_size;

	if (ctx->unknown_charset) {
		/* we don't know the source charset, so assume we want to
		   match using same charsets */
		charset = NULL;
	} else if (charset != NULL && strcasecmp(charset, "x-unknown") == 0) {
		/* compare with same charset as search key. the key is already
		   in utf-8 so we can't use charset = NULL comparing. */
		charset = ctx->key_charset;
	}

	utf8_data = charset_to_ucase_utf8_string(charset, NULL, data, size,
						 &utf8_size);

	if (utf8_data == NULL) {
		/* unknown character set, or invalid data. just compare it
		   directly so at least ASCII comparision works. */
		utf8_data = str_ucase(p_strndup(unsafe_data_stack_pool,
						data, size));
		utf8_size = size;
	}

	search_loop(ctx, utf8_data, utf8_size);
}

static bool search_block(const unsigned char *data, size_t size,
			 const char *charset, void *context)
{
	struct message_header_search_context *ctx = context;

	t_push();
	search_with_charset(data, size, charset, ctx);
	t_pop();
	return !ctx->found;
}

bool message_header_search(struct message_header_search_context *ctx,
			   const unsigned char *header_block, size_t size)
{
	if (!ctx->found)
		message_header_decode(header_block, size, search_block, ctx);
	return ctx->found;
}

void message_header_search_reset(struct message_header_search_context *ctx)
{
	buffer_set_used_size(ctx->match_buf, 0);
	ctx->found = FALSE;
}
