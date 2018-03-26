/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "str.h"
#include "charset-utf8-private.h"

#include <ctype.h>

#ifdef HAVE_ICONV
const struct charset_utf8_vfuncs *charset_utf8_vfuncs = &charset_iconv;
#else
const struct charset_utf8_vfuncs *charset_utf8_vfuncs = &charset_utf8only;
#endif

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

struct charset_translation *
charset_utf8_to_utf8_begin(normalizer_func_t *normalizer)
{
	struct charset_translation *trans;

	if (charset_to_utf8_begin("UTF-8", normalizer, &trans) < 0)
		i_unreached();
	return trans;
}

enum charset_result
charset_utf8_to_utf8(normalizer_func_t *normalizer,
		     const unsigned char *src, size_t *src_size, buffer_t *dest)
{
	enum charset_result res = CHARSET_RET_OK;
	size_t pos;

	uni_utf8_partial_strlen_n(src, *src_size, &pos);
	if (pos < *src_size) {
		i_assert(*src_size - pos <= CHARSET_MAX_PENDING_BUF_SIZE);
		*src_size = pos;
		res = CHARSET_RET_INCOMPLETE_INPUT;
	}

	if (normalizer != NULL) {
		if (normalizer(src, *src_size, dest) < 0)
			return CHARSET_RET_INVALID_INPUT;
	} else if (!uni_utf8_get_valid_data(src, *src_size, dest)) {
		return CHARSET_RET_INVALID_INPUT;
	} else {
		buffer_append(dest, src, *src_size);
	}
	return res;
}

int charset_to_utf8_begin(const char *charset, normalizer_func_t *normalizer,
			  struct charset_translation **t_r)
{
	return charset_utf8_vfuncs->to_utf8_begin(charset, normalizer, t_r);
}

void charset_to_utf8_end(struct charset_translation **_t)
{
	struct charset_translation *t = *_t;

	*_t = NULL;
	charset_utf8_vfuncs->to_utf8_end(t);
}

void charset_to_utf8_reset(struct charset_translation *t)
{
	charset_utf8_vfuncs->to_utf8_reset(t);
}

enum charset_result
charset_to_utf8(struct charset_translation *t,
		const unsigned char *src, size_t *src_size, buffer_t *dest)
{
	return charset_utf8_vfuncs->to_utf8(t, src, src_size, dest);
}
