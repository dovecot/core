/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "base64.h"
#include "buffer.h"
#include "str-find.h"
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

	struct str_find_context *str_find_ctx;

	unsigned int found:1;
	unsigned int last_lf:1;
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
	ctx->str_find_ctx = str_find_init(pool, key);

	i_assert(ctx->key_len <= SSIZE_T_MAX/sizeof(size_t));
	t_pop();
	return 1;
}

void message_header_search_deinit(struct message_header_search_context **_ctx)
{
        struct message_header_search_context *ctx = *_ctx;
	pool_t pool;

	*_ctx = NULL;

	str_find_deinit(&ctx->str_find_ctx);

	pool = ctx->pool;
	p_free(pool, ctx->key);
	p_free(pool, ctx->key_charset);
	p_free(pool, ctx);
}

static bool search_with_charset(const unsigned char *data, size_t size,
				const char *charset,
				struct message_header_search_context *ctx)
{
	const char *utf8_data;
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

	return str_find_more(ctx->str_find_ctx, utf8_data, utf8_size);
}

static bool search_block(const unsigned char *data, size_t size,
			 const char *charset, void *context)
{
	struct message_header_search_context *ctx = context;

	t_push();
	ctx->found = search_with_charset(data, size, charset, ctx);
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
	str_find_reset(ctx->str_find_ctx);
	ctx->last_lf = FALSE;
	ctx->found = FALSE;
}
