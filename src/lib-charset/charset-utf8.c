/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "charset-utf8.h"

#ifndef HAVE_ICONV_H

#include <ctype.h>

struct _CharsetTranslation {
	int dummy;
};

static CharsetTranslation ascii_translation, utf8_translation;

CharsetTranslation *charset_to_utf8_begin(const char *charset,
					  int *unknown_charset)
{
	if (unknown_charset != NULL)
		*unknown_charset = FALSE;

	if (strcasecmp(charset, "us-ascii") == 0 ||
	    strcasecmp(charset, "ascii") == 0)
		return &ascii_translation;

	if (strcasecmp(charset, "UTF-8") == 0 ||
	    strcasecmp(charset, "UTF8") == 0)
		return &utf8_translation;

	/* no support for charsets that need translation */
	if (unknown_charset != NULL)
		*unknown_charset = TRUE;
	return NULL;
}

void charset_to_utf8_end(CharsetTranslation *t __attr_unused__)
{
}

void charset_to_utf8_reset(CharsetTranslation *t __attr_unused__)
{
}

int charset_to_ucase_utf8(CharsetTranslation *t __attr_unused__,
			  const unsigned char **inbuf, size_t *insize,
			  unsigned char *outbuf, size_t *outsize)
{
	size_t max_size, i;

	max_size = I_MIN(*insize, *outsize);
	for (i = 0; i < max_size; i++)
		outbuf[i] = i_toupper((*inbuf)[i]); /* FIXME: utf8 */

	*insize = 0;
	*outsize = max_size;

	return TRUE;
}

const char *
charset_to_ucase_utf8_string(const char *charset, int *unknown_charset,
			     const unsigned char *buf,
			     size_t *size __attr_unused__)
{
	if (charset == NULL || strcasecmp(charset, "us-ascii") == 0 ||
	    strcasecmp(charset, "ascii") == 0 ||
	    strcasecmp(charset, "UTF-8") == 0 ||
	    strcasecmp(charset, "UTF8") == 0)
		return str_ucase(t_strdup_noconst(buf)); /* FIXME: utf8 */

	if (unknown_charset != NULL)
		*unknown_charset = TRUE;
	return NULL;
}

#endif
