/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "buffer.h"
#include "charset-utf8.h"

#include <ctype.h>

void _charset_utf8_ucase(const unsigned char *src, size_t src_size,
			 Buffer *dest, size_t destpos)
{
	char *destbuf;
	size_t i;

	destbuf = buffer_get_space(dest, destpos, src_size);
	for (i = 0; i < src_size; i++)
		destbuf[i] = i_toupper(src[i]); /* FIXME: utf8 */
}

const char *_charset_utf8_ucase_strdup(const Buffer *data, size_t *utf8_size)
{
	const char *buf;
	size_t size;
	Buffer *dest;

	buf = buffer_get_data(data, &size);

	dest = buffer_create_dynamic(data_stack_pool, size, (size_t)-1);
	_charset_utf8_ucase(buf, size, dest, 0);
	if (utf8_size != NULL)
		*utf8_size = buffer_get_used_size(dest);
	buffer_append_c(dest, '\0');
	return buffer_free_without_data(dest);
}


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

CharsetResult
charset_to_ucase_utf8(CharsetTranslation *t __attr_unused__,
		      const Buffer *src, size_t *src_pos, Buffer *dest)
{
	size_t size, destpos, destleft;

	destpos = buffer_get_used_size(dest);
	destleft = buffer_get_size(dest) - destpos;

	/* no translation needed - just copy it to outbuf uppercased */
	size = buffer_get_used_size(src);
	if (size > destleft)
		size = destleft;
	_charset_utf8_ucase(buffer_get_data(src, NULL), size, dest, destpos);
	if (src_pos != NULL)
		*src_pos = size;
	return CHARSET_RET_OK;
}

const char *
charset_to_ucase_utf8_string(const char *charset, int *unknown_charset,
			     const Buffer *data, size_t *utf8_size)
{
	if (charset == NULL || strcasecmp(charset, "us-ascii") == 0 ||
	    strcasecmp(charset, "ascii") == 0 ||
	    strcasecmp(charset, "UTF-8") == 0 ||
	    strcasecmp(charset, "UTF8") == 0) {
		if (unknown_charset != NULL)
			*unknown_charset = FALSE;
		return _charset_utf8_ucase_strdup(data, utf8_size);
	} else {
		if (unknown_charset != NULL)
			*unknown_charset = TRUE;
		return NULL;
	}
}

#endif
