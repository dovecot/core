/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "buffer.h"
#include "charset-utf8.h"

#include <ctype.h>

void _charset_utf8_ucase(const unsigned char *src, size_t src_size,
			 buffer_t *dest, size_t destpos)
{
	char *destbuf;
	size_t i;

	destbuf = buffer_get_space(dest, destpos, src_size);
	for (i = 0; i < src_size; i++)
		destbuf[i] = i_toupper(src[i]); /* FIXME: utf8 */
}

const char *_charset_utf8_ucase_strdup(const unsigned char *data, size_t size,
				       size_t *utf8_size_r)
{
	buffer_t *dest;

	dest = buffer_create_dynamic(data_stack_pool, size, (size_t)-1);
	_charset_utf8_ucase(data, size, dest, 0);
	if (utf8_size_r != NULL)
		*utf8_size_r = buffer_get_used_size(dest);
	buffer_append_c(dest, '\0');
	return buffer_free_without_data(dest);
}


#ifndef HAVE_ICONV_H

#include <ctype.h>

struct _CharsetTranslation {
	int dummy;
};

static struct charset_translation ascii_translation, utf8_translation;

struct charset_translation *charset_to_utf8_begin(const char *charset,
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

void charset_to_utf8_end(struct charset_translation *t __attr_unused__)
{
}

void charset_to_utf8_reset(struct charset_translation *t __attr_unused__)
{
}

enum charset_result
charset_to_ucase_utf8(struct charset_translation *t __attr_unused__,
		      const unsigned char *src, size_t *src_size,
		      buffer_t *dest)
{
	size_t destpos, destleft;

	destpos = buffer_get_used_size(dest);
	destleft = buffer_get_size(dest) - destpos;

	/* no translation needed - just copy it to outbuf uppercased */
	if (*src_size > destleft)
		*src_size = destleft;
	_charset_utf8_ucase(src, *src_size, dest, destpos);
	return CHARSET_RET_OK;
}

const char *
charset_to_utf8_string(const char *charset, int *unknown_charset,
		       const unsigned char *data, size_t size,
		       size_t *utf8_size_r)
{
	if (charset == NULL || strcasecmp(charset, "us-ascii") == 0 ||
	    strcasecmp(charset, "ascii") == 0 ||
	    strcasecmp(charset, "UTF-8") == 0 ||
	    strcasecmp(charset, "UTF8") == 0) {
		if (unknown_charset != NULL)
			*unknown_charset = FALSE;
		if (utf8_size_r != NULL)
			*utf8_size_r = size;
		return t_strndup(data, size);
	} else {
		if (unknown_charset != NULL)
			*unknown_charset = TRUE;
		return NULL;
	}
}

const char *
charset_to_ucase_utf8_string(const char *charset, int *unknown_charset,
			     const unsigned char *data, size_t size,
			     size_t *utf8_size_r)
{
	if (charset == NULL || strcasecmp(charset, "us-ascii") == 0 ||
	    strcasecmp(charset, "ascii") == 0 ||
	    strcasecmp(charset, "UTF-8") == 0 ||
	    strcasecmp(charset, "UTF8") == 0) {
		if (unknown_charset != NULL)
			*unknown_charset = FALSE;
		return _charset_utf8_ucase_strdup(data, size, utf8_size_r);
	} else {
		if (unknown_charset != NULL)
			*unknown_charset = TRUE;
		return NULL;
	}
}

#endif
