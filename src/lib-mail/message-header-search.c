/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "base64.h"
#include "hex-binary.h"
#include "charset-utf8.h"
#include "rfc822-tokenize.h"
#include "message-header-search.h"

#include <ctype.h>

struct _HeaderSearchContext {
	const unsigned char *key;
	size_t key_len;

	size_t *matches; /* size of strlen(key) */
	ssize_t match_count;

	unsigned int last_newline:1;
	unsigned int submatch:1;
	unsigned int eoh:1;
	unsigned int unknown_charset:1;
};

HeaderSearchContext *
message_header_search_init(Pool pool, const char *key, const char *charset,
			   int *unknown_charset)
{
	HeaderSearchContext *ctx;
	size_t size;

	ctx = p_new(pool, HeaderSearchContext, 1);

	/* get the key uppercased */
	size = strlen(key);
	ctx->key = charset_to_ucase_utf8((const unsigned char *) key, &size,
					 charset, unknown_charset);
	if (ctx->key == NULL)
		return NULL;

	ctx->key = p_strdup(pool, ctx->key);
	ctx->key_len = size;
	ctx->unknown_charset = charset == NULL;

	ctx->matches = p_malloc(pool, sizeof(size_t) * ctx->key_len);
	i_assert(ctx->key_len <= SSIZE_T_MAX);
	return ctx;
}

static size_t quoted_printable_decode(const unsigned char *src, size_t size,
				      unsigned char *dest)
{
	const unsigned char *end;
	unsigned char *dest_start;
	char hexbuf[3];

	hexbuf[2] = '\0';

	dest_start = dest;
	end = src + size;

	for (; src != end; src++) {
		if (*src == '_') {
			*dest++ = ' ';
			continue;
		}

		if (*src == '=' && src+2 < end) {
			hexbuf[0] = src[1];
			hexbuf[1] = src[2];

			if (hex_to_binary(hexbuf, dest) == 1) {
				dest++;
				src += 2;
				continue;
			}
		}

		*dest++ = *src;
	}

	return (size_t) (dest - dest_start);
}

static int match_data(const unsigned char *data, size_t size,
		      const char *charset, HeaderSearchContext *ctx)
{
	int ret;

	if (ctx->unknown_charset) {
		/* we don't know the source charset, so assume we want to
		   match using same charsets */
		charset = NULL;
	}

	data = (const unsigned char *) charset_to_ucase_utf8(data, &size,
							     charset, NULL);
	if (data == NULL) {
		/* unknown character set, or invalid data */
		return FALSE;
	}

	ctx->submatch = TRUE;
	ret = message_header_search(data, &size, ctx);
	ctx->submatch = FALSE;

	return ret;
}

static int match_encoded(const unsigned char **start, const unsigned char *end,
			 HeaderSearchContext *ctx)
{
	const unsigned char *p, *encoding, *text, *new_end;
	const char *charset;
	unsigned char *buf;
	ssize_t size;
	int ok, ret;

	/* first split the string =?charset?encoding?text?= */
	ok = FALSE;
	charset = (const char *) *start; encoding = NULL; text = NULL;
	for (p = *start; p != end; p++) {
		if (*p == '?') {
			if (encoding == NULL) {
				charset = t_strdup_until(charset, p);
				encoding = p+1;
			} else if (text == NULL) {
				if (p != encoding+1)
					encoding = "?";
				else if (*encoding == 'Q' || *encoding == 'q')
					encoding = "Q";
				else if (*encoding == 'B' || *encoding == 'b')
					encoding = "B";
				else
					encoding = "?";

				text = p+1;
			} else {
				new_end = p;

				p++;
				if (p != end && *p == '=')
					p++;

				end = new_end;
				*start = p-1;
				ok = TRUE;
				break;
			}
		}
	}

	if (ok && *encoding != '?') {
		t_push();

		size = (ssize_t) (end - text);
		buf = t_malloc(size);

		if (*encoding == 'Q')
			size = quoted_printable_decode(text, size, buf);
		else
			size = base64_decode(text, size, buf);

		if (size >= 0) {
			/* non-corrupted encoding */
			ret = match_data(buf, size, charset, ctx);
			t_pop();
			return ret;
		}

		t_pop();
	}

	/* non-supported encoding, we can't match it */
	ctx->match_count = 0;
	return FALSE;
}

int message_header_search(const unsigned char *header_block,
			  size_t *header_size, HeaderSearchContext *ctx)
{
	const unsigned char *p, *end;
	unsigned char chr;
	ssize_t i;
	int found;

	if (ctx->eoh || *header_size == 0)
		return FALSE;

	end = header_block + *header_size;

	found = FALSE;
	for (p = header_block; p != end; p++) {
		if (p[0] == '=' && p+1 != end && p[1] == '?' &&
		    !ctx->submatch) {
			/* encoded string. read it. */
			p += 2;
			if (match_encoded(&p, end, ctx)) {
				found = TRUE;
				break;
			}

			i_assert(p != end);
			continue;
		}

		chr = ctx->submatch || (*p & 0x80) != 0 ? *p : i_toupper(*p);

		if (((p == header_block && ctx->last_newline) ||
		     (p != header_block && p[-1] == '\n')) && !ctx->submatch) {
			/* newline */
			if (!IS_LWSP(*p)) {
				/* not a long header, reset matches */
				ctx->match_count = 0;

				/* and see if we're at end of header */
				if (*p == '\n') {
					p++;
					ctx->eoh = TRUE;
					break;
				}

				if (*p == '\r' && p[1] == '\n') {
					p += 2;
					ctx->eoh = TRUE;
					break;
				}
			}
			chr = ' ';
		}

		if (*p == '\r' || *p == '\n')
			continue;

		for (i = ctx->match_count-1; i >= 0; i--) {
			if (ctx->key[ctx->matches[i]] == chr) {
				if (++ctx->matches[i] == ctx->key_len) {
					/* full match */
					p++;
					found = TRUE;
					break;
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

		if (found)
			break;

		if (chr == ctx->key[0]) {
			if (ctx->key_len == 1) {
				/* only one character in search key */
				p++;
				found = TRUE;
				break;
			}
			i_assert((size_t)ctx->match_count < ctx->key_len);
			ctx->matches[ctx->match_count++] = 1;
		}
	}

	*header_size = (size_t) (p - header_block);

	ctx->last_newline = end[-1] == '\n';
	return found;
}

void message_header_search_reset(HeaderSearchContext *ctx)
{
	ctx->eoh = FALSE;
	ctx->match_count = 0;
}
