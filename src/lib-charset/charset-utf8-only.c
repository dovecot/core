/* Copyright (c) 2002-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "charset-utf8.h"

#ifndef HAVE_ICONV

struct charset_translation {
	normalizer_func_t *normalizer;
};

int charset_to_utf8_begin(const char *charset, normalizer_func_t *normalizer,
			  struct charset_translation **t_r)
{
	struct charset_translation *t;

	if (!charset_is_utf8(charset)) {
		/* no support for charsets that need translation */
		return -1;
	}

	t = i_new(struct charset_translation, 1);
	t->normalizer = normalizer;
	*t_r = t;
	return 0;
}

void charset_to_utf8_end(struct charset_translation **_t)
{
	struct charset_translation *t = *_t;

	*_t = NULL;
	i_free(t);
}

void charset_to_utf8_reset(struct charset_translation *t ATTR_UNUSED)
{
}

enum charset_result
charset_to_utf8(struct charset_translation *t,
		const unsigned char *src, size_t *src_size, buffer_t *dest)
{
	return charset_utf8_to_utf8(t->normalizer, src, src_size, dest);
}

#endif
