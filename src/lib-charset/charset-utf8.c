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

void charset_utf8_ucase_write(buffer_t *dest, size_t destpos,
			      const unsigned char *src, size_t src_size)
{
	char *destbuf;
	size_t i;

	destbuf = buffer_get_space_unsafe(dest, destpos, src_size);
	for (i = 0; i < src_size; i++)
		destbuf[i] = i_toupper(src[i]); /* FIXME: utf8 */
}

const char *charset_utf8_ucase_strdup(const unsigned char *data, size_t size,
				      size_t *utf8_size_r)
{
	buffer_t *dest;

	dest = buffer_create_dynamic(pool_datastack_create(), size);
	charset_utf8_ucase_write(dest, 0, data, size);
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
	if (t == &utf8_translation_uc || t == &ascii_translation_uc)
		charset_utf8_ucase_write(dest, dest->used, src, *src_size);
	else
		buffer_append(dest, src, *src_size);
	return CHARSET_RET_OK;
}

#endif
