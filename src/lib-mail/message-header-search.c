/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "base64.h"
#include "buffer.h"
#include "charset-utf8.h"
#include "rfc822-tokenize.h"
#include "quoted-printable.h"
#include "message-header-search.h"

#include <ctype.h>

struct _HeaderSearchContext {
	Pool pool;

	unsigned char *key;
	size_t key_len;
	char *key_charset;

	size_t *matches; /* size of strlen(key) */
	ssize_t match_count;

	unsigned int found:1;
	unsigned int last_newline:1;
	unsigned int submatch:1;
	unsigned int key_ascii:1;
	unsigned int unknown_charset:1;
};

HeaderSearchContext *
message_header_search_init(Pool pool, const char *key, const char *charset,
			   int *unknown_charset)
{
	HeaderSearchContext *ctx;
	Buffer *keybuf;
	size_t key_len;
	const char *p;

	ctx = p_new(pool, HeaderSearchContext, 1);
	ctx->pool = pool;

	/* get the key uppercased */
	keybuf = buffer_create_const_data(data_stack_pool, key, strlen(key));
	key = charset_to_ucase_utf8_string(charset, unknown_charset,
					   keybuf, &key_len);

	if (key == NULL) {
		/* invalid key */
		t_pop();
		return NULL;
	}

	ctx->key = p_strdup(pool, key);
	ctx->key_len = key_len;
	ctx->key_charset = p_strdup(pool, charset);
	ctx->unknown_charset = charset == NULL;

	ctx->key_ascii = TRUE;
	for (p = ctx->key; *p != '\0'; p++) {
		if ((*p & 0x80) != 0) {
			ctx->key_ascii = FALSE;
			break;
		}
	}

	i_assert(ctx->key_len <= SSIZE_T_MAX/sizeof(size_t));
	ctx->matches = p_new(pool, size_t, ctx->key_len);
	return ctx;
}

void message_header_search_free(HeaderSearchContext *ctx)
{
	Pool pool;

	pool = ctx->pool;
	p_free(pool, ctx->key);
	p_free(pool, ctx->key_charset);
	p_free(pool, ctx->matches);
	p_free(pool, ctx);
}

static int match_data(const Buffer *buffer, const char *charset,
		      HeaderSearchContext *ctx)
{
	const char *utf8_data;
	size_t size;
	int ret;

	if (ctx->unknown_charset) {
		/* we don't know the source charset, so assume we want to
		   match using same charsets */
		charset = NULL;
	} else if (charset != NULL && strcasecmp(charset, "x-unknown") == 0) {
		/* compare with same charset as search key. the key is already
		   in utf-8 so we can't use charset = NULL comparing. */
		charset = ctx->key_charset;
	}

	utf8_data = charset_to_ucase_utf8_string(charset, NULL, buffer, &size);
	if (utf8_data == NULL) {
		/* unknown character set, or invalid data */
		return FALSE;
	}

	ctx->submatch = TRUE;
	ret = message_header_search(utf8_data, size, ctx);
	ctx->submatch = FALSE;

	return ret;
}

static int split_encoded(Buffer *buffer, size_t *last_pos,
			 const char **charset, const char **encoding)
{
	const char *p;
	size_t size, pos, textpos;

	p = buffer_get_data(buffer, &size);

	/* get charset */
	for (pos = 0; pos < size && p[pos] != '?'; pos++) ;
	if (p[pos] != '?') return FALSE;
	*charset = t_strndup(p, pos);

	/* get encoding */
	pos++;
	if (pos+2 >= size || p[pos+1] != '?')
		return FALSE;

	if (p[pos] == 'Q' || p[pos] == 'q')
		*encoding = "Q";
	else if (p[pos] == 'B' || p[pos] == 'b')
		*encoding = "B";
	else
		return FALSE;

	/* get text */
	pos += 2;
	textpos = pos;
	for (; pos < size && p[pos] != '?'; pos++) ;
	if (p[pos] != '?' || pos+1 >= size || p[pos+1] != '=') return FALSE;

	buffer_set_limit(buffer, pos);
	buffer_set_start_pos(buffer, textpos + buffer_get_start_pos(buffer));
	*last_pos = pos+1;

	return TRUE;
}

static int match_encoded(Buffer *buffer, size_t *last_pos,
			 HeaderSearchContext *ctx)
{
	const char *charset, *encoding, *text;
	Buffer *decodebuf;
	size_t textsize;

	/* first split the string charset?encoding?text?= */
	if (!split_encoded(buffer, last_pos, &charset, &encoding)) {
		ctx->match_count = 0;
		return FALSE;
	}

	/* buffer is now limited to only the text portion */
	text = buffer_get_data(buffer, &textsize);
	decodebuf = buffer_create_static_hard(data_stack_pool, textsize);

	if (*encoding == 'Q')
		quoted_printable_decode(text, textsize, NULL, decodebuf);
	else {
		if (base64_decode(text, textsize, NULL, decodebuf) < 0) {
			/* corrupted encoding */
			ctx->match_count = 0;
			return FALSE;
		}
	}

	return match_data(decodebuf, charset, ctx);
}

int message_header_search(const unsigned char *header_block, size_t size,
			  HeaderSearchContext *ctx)
{
	Buffer *buf;
	ssize_t i;
	size_t pos, subpos;
	unsigned char chr;
	int last_newline, ret;

	if (ctx->found)
		return TRUE;

	t_push();
	buf = buffer_create_const_data(data_stack_pool, header_block, size);

	last_newline = ctx->last_newline;
	for (pos = 0; pos < size; pos++) {
		chr = header_block[pos];

		if (chr == '=' && pos+1 < size &&
		    header_block[pos+1] == '?' && !ctx->submatch) {
			/* encoded string. read it. */
                        buffer_set_start_pos(buf, pos+2);

			t_push();
			ret = match_encoded(buf, &subpos, ctx);
			t_pop();

			if (ret) {
				ctx->found = TRUE;
				break;
			}

			buffer_set_start_pos(buf, 0);
			buffer_set_limit(buf, (size_t)-1);

			pos += subpos - 1;
			last_newline = FALSE;
			continue;
		}

		if (!ctx->submatch) {
			if ((chr & 0x80) == 0)
				chr = i_toupper(chr);
			else if (!ctx->key_ascii && !ctx->unknown_charset) {
				/* we have non-ascii in header and key contains
				   non-ascii characters. treat the rest of the
				   header as encoded with the key's charset */
				t_push();
				ctx->found = match_data(buf, ctx->key_charset,
							ctx);
				t_pop();
				break;
			}
		}

		if (last_newline && !ctx->submatch) {
			if (!IS_LWSP(chr)) {
				/* not a long header, reset matches */
				ctx->match_count = 0;
			}
			chr = ' ';
		}
		last_newline = chr == '\n';

		if (chr == '\r' || chr == '\n')
			continue;

		for (i = ctx->match_count-1; i >= 0; i--) {
			if (ctx->key[ctx->matches[i]] == chr) {
				if (++ctx->matches[i] == ctx->key_len) {
					/* full match */
					ctx->found = TRUE;
					t_pop();
					return TRUE;
				}
			} else {
				/* non-match */
				ctx->match_count--;
				if (i != ctx->match_count) {
					memmove(ctx->matches + i,
						ctx->matches + i + 1,
						ctx->match_count - i);
				}
			}
		}

		if (chr == ctx->key[0]) {
			if (ctx->key_len == 1) {
				/* only one character in search key */
				ctx->found = TRUE;
				break;
			}
			i_assert((size_t)ctx->match_count < ctx->key_len);
			ctx->matches[ctx->match_count++] = 1;
		}
	}
	t_pop();

	ctx->last_newline = last_newline;
	return ctx->found;
}

void message_header_search_reset(HeaderSearchContext *ctx)
{
	ctx->match_count = 0;
	ctx->found = FALSE;
}
