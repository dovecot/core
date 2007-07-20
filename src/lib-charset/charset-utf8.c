/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "buffer.h"
#include "charset-utf8.h"

#include <ctype.h>

bool charset_is_utf8(const char *charset)
{
	return strcasecmp(charset, "us-ascii") == 0 ||
		strcasecmp(charset, "ascii") == 0 ||
		strcasecmp(charset, "UTF-8") == 0 ||
		strcasecmp(charset, "UTF8") == 0;
}

#ifndef HAVE_ICONV

#include <ctype.h>

struct charset_translation {
	int dummy;
};

static struct charset_translation ascii_translation, utf8_translation;
static struct charset_translation ascii_translation_uc, utf8_translation_uc;

struct charset_translation *
charset_to_utf8_begin(const char *charset, bool ucase, bool *unknown_charset_r)
{
	if (unknown_charset_r != NULL)
		*unknown_charset_r = FALSE;

	if (strcasecmp(charset, "us-ascii") == 0 ||
	    strcasecmp(charset, "ascii") == 0)
		return ucase ? &ascii_translation_uc : &ascii_translation;

	if (strcasecmp(charset, "UTF-8") == 0 ||
	    strcasecmp(charset, "UTF8") == 0)
		return ucase ? &utf8_translation_uc : &utf8_translation;

	/* no support for charsets that need translation */
	if (unknown_charset_r != NULL)
		*unknown_charset_r = TRUE;
	return NULL;
}

void charset_to_utf8_end(struct charset_translation **t __attr_unused__)
{
}

void charset_to_utf8_reset(struct charset_translation *t __attr_unused__)
{
}

enum charset_result
charset_to_utf8(struct charset_translation *t,
		const unsigned char *src, size_t *src_size, buffer_t *dest)
{
	if (t != &utf8_translation_uc && t != &ascii_translation_uc) {
		buffer_append(dest, src, *src_size);
		return CHARSET_RET_OK;
	}
	if (uni_utf8_to_decomposed_titlecase(src, *src_size, dest) < 0)
		return CHARSET_RET_INVALID_INPUT;
	return CHARSET_RET_OK;
}

#endif
