/* Copyright (c) 2002-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "str.h"
#include "unichar.h"
#include "charset-utf8.h"

#include <ctype.h>

bool charset_is_utf8(const char *charset)
{
	return strcasecmp(charset, "us-ascii") == 0 ||
		strcasecmp(charset, "ascii") == 0 ||
		strcasecmp(charset, "UTF-8") == 0 ||
		strcasecmp(charset, "UTF8") == 0;
}

int charset_to_utf8_str(const char *charset, normalizer_func_t *normalizer,
			const char *input, string_t *output,
			enum charset_result *result_r)
{
	struct charset_translation *t;
	size_t len = strlen(input);

	if (charset_to_utf8_begin(charset, normalizer, &t) < 0)
		return -1;

	*result_r = charset_to_utf8(t, (const unsigned char *)input,
				    &len, output);
	charset_to_utf8_end(&t);
	return 0;
}

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
	if (t->normalizer != NULL) {
		if (t->normalizer(src, *src_size, dest) < 0)
			return CHARSET_RET_INVALID_INPUT;
	} else if (!uni_utf8_get_valid_data(src, *src_size, dest)) {
		return CHARSET_RET_INVALID_INPUT;
	} else {
		buffer_append(dest, src, *src_size);
	}
	return CHARSET_RET_OK;
}

#endif
