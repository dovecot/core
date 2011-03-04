/* Copyright (c) 2007-2011 Dovecot authors, see the included COPYING file */

/* @UNSAFE: whole file */

#include "lib.h"
#include "str-find.h"

struct str_find_context {
	pool_t pool;
	unsigned char *key;
	unsigned int key_len;

	unsigned int *matches;
	unsigned int match_count;

	size_t match_end_pos;

	int badtab[UCHAR_MAX+1];
	int goodtab[FLEXIBLE_ARRAY_MEMBER];
};

static void init_badtab(struct str_find_context *ctx)
{
	unsigned int i, len_1 = ctx->key_len - 1;

	for (i = 0; i <= UCHAR_MAX; i++)
		ctx->badtab[i] = ctx->key_len;

	for (i = 0; i < len_1; i++)
		ctx->badtab[ctx->key[i]] = len_1 - i;
}

static void init_suffixes(struct str_find_context *ctx, unsigned int *suffixes)
{
	unsigned int len_1 = ctx->key_len - 1;
	int f = 0, g, i;

	suffixes[len_1] = ctx->key_len;
	g = len_1;
	for (i = ctx->key_len - 2; i >= 0; i--) {
		if (i > g && (int)suffixes[i + len_1 - f] < i - g)
			suffixes[i] = suffixes[i + len_1 - f];
		else {
			if (i < g)
				g = i;
			f = i;
			while (g >= 0 && ctx->key[g] == ctx->key[g + len_1 - f])
				g--;
			suffixes[i] = f - g;
		}
	}
}

static void init_goodtab(struct str_find_context *ctx)
{
	unsigned int len_1 = ctx->key_len - 1;
	unsigned int j, *suffixes;
	int i;

	suffixes = t_buffer_get(sizeof(*suffixes) * ctx->key_len);
	init_suffixes(ctx, suffixes);

	for (i = 0; i < (int)ctx->key_len; i++)
		ctx->goodtab[i] = ctx->key_len;

	j = 0;
	for (i = len_1; i >= -1; i--) {
		if (i < 0 || suffixes[i] == (unsigned int)i + 1) {
			for (; j < len_1 - i; j++) {
				if (ctx->goodtab[j] == (int)ctx->key_len)
					ctx->goodtab[j] = len_1 - i;
			}
		}
	}
	for (i = 0; i <= (int)ctx->key_len - 2; i++)
		ctx->goodtab[len_1 - suffixes[i]] = len_1 - i;
}

struct str_find_context *str_find_init(pool_t pool, const char *key)
{
	struct str_find_context *ctx;
	unsigned int key_len = strlen(key);

	i_assert(key_len > 0);

	ctx = p_malloc(pool, sizeof(struct str_find_context) +
		       sizeof(ctx->goodtab[0]) * key_len);
	ctx->pool = pool;
	ctx->matches = p_new(pool, unsigned int, key_len);
	ctx->key_len = key_len;
	ctx->key = p_malloc(pool, key_len);
	memcpy(ctx->key, key, key_len);

	init_goodtab(ctx);
	init_badtab(ctx);
	return ctx;
}

void str_find_deinit(struct str_find_context **_ctx)
{
	struct str_find_context *ctx = *_ctx;

	*_ctx = NULL;
	p_free(ctx->pool, ctx->matches);
	p_free(ctx->pool, ctx->key);
	p_free(ctx->pool, ctx);
}

bool str_find_more(struct str_find_context *ctx,
		    const unsigned char *data, size_t size)
{
	unsigned int key_len = ctx->key_len;
	unsigned int i, j, a, b;
	int bad_value;

	for (i = j = 0; i < ctx->match_count; i++) {
		a = ctx->matches[i];
		if (ctx->matches[i] + size >= key_len) {
			/* we can fully determine this match now */
			for (; a < key_len; a++) {
				if (ctx->key[a] != data[a - ctx->matches[i]])
					break;
			}

			if (a == key_len) {
				ctx->match_end_pos = key_len - ctx->matches[i];
				return TRUE;
			}
		} else {
			for (b = 0; b < size; b++) {
				if (ctx->key[a+b] != data[b])
					break;
			}

			if (b == size)
				ctx->matches[j++] = a + size;
		}
	}
	if (j > 0) {
		i_assert(j + size < key_len);
		ctx->match_count = j;
		j = 0;
	} else {
		/* Boyer-Moore searching */
		j = 0;
		while (j + key_len <= size) {
			i = key_len - 1;
			while (ctx->key[i] == data[i + j]) {
				if (i == 0) {
					ctx->match_end_pos = j + key_len;
					return TRUE;
				}
				i--;
			}

			bad_value = ctx->badtab[data[i + j]] + i + 1 - key_len;
			j += I_MAX(ctx->goodtab[i], bad_value);
		}
		i_assert(j <= size);
		ctx->match_count = 0;
	}

	for (; j < size; j++) {
		for (i = j; i < size; i++) {
			if (ctx->key[i-j] != data[i])
				break;
		}
		if (i == size)
			ctx->matches[ctx->match_count++] = size - j;
	}
	return FALSE;
}

size_t str_find_get_match_end_pos(struct str_find_context *ctx)
{
	return ctx->match_end_pos;
}

void str_find_reset(struct str_find_context *ctx)
{
	ctx->match_count = 0;
}
