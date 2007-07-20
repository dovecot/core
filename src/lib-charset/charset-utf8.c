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

void _charset_utf8_ucase(const unsigned char *src, size_t src_size,
			 buffer_t *dest, size_t destpos)
{
	char *destbuf;
	size_t i;

	destbuf = buffer_get_space_unsafe(dest, destpos, src_size);
	for (i = 0; i < src_size; i++)
		destbuf[i] = i_toupper(src[i]); /* FIXME: utf8 */
}

const char *_charset_utf8_ucase_strdup(const unsigned char *data, size_t size,
				       size_t *utf8_size_r)
{
	buffer_t *dest;

	dest = buffer_create_dynamic(pool_datastack_create(), size);
	_charset_utf8_ucase(data, size, dest, 0);
	if (utf8_size_r != NULL)
		*utf8_size_r = buffer_get_used_size(dest);
	buffer_append_c(dest, '\0');
	return buffer_free_without_data(dest);
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
	size_t destpos = dest->used, destleft;

	destleft = buffer_get_size(dest) - destpos;
	if (*src_size > destleft)
		*src_size = destleft;

	/* no translation needed - just copy it to outbuf uppercased */
	if (t == &utf8_translation_uc || t == &ascii_translation_uc)
		_charset_utf8_ucase(src, *src_size, dest, destpos);
	else
		buffer_write(dest, destpos, src, *src_size);
	return CHARSET_RET_OK;
}

enum charset_result
charset_to_utf8_full(struct charset_translation *t,
		     const unsigned char *src, size_t *src_size,
		     buffer_t *dest)
{
	if (t == &utf8_translation_uc || t == &ascii_translation_uc)
		_charset_utf8_ucase(src, *src_size, dest, dest->used);
	else
		buffer_append(dest, src, *src_size);
	return CHARSET_RET_OK;
}

const char *
charset_to_utf8_string(const char *charset, bool *unknown_charset,
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
charset_to_ucase_utf8_string(const char *charset, bool *unknown_charset,
			     const unsigned char *data, size_t size,
			     size_t *utf8_size_r)
{
	if (charset == NULL || charset_is_utf8(charset)) {
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
