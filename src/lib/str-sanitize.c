/* Copyright (c) 2004-2007 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "str-sanitize.h"

static size_t str_sanitize_skip_start(const char *src, size_t max_len)
{
	size_t i;

	for (i = 0; i < max_len; i++) {
		if (((unsigned char)src[i] & 0x7f) < 32)
			break;
	}
	return i;
}

void str_sanitize_append(string_t *dest, const char *src, size_t max_len)
{
	size_t i;

	i = str_sanitize_skip_start(src, max_len);
	str_append_n(dest, src, i);

	for (; i < max_len && src[i] != '\0'; i++) {
		if (((unsigned char)src[i] & 0x7f) < 32)
			str_append_c(dest, '?');
		else
			str_append_c(dest, src[i]);
	}

	if (src[i] != '\0') {
		str_truncate(dest, str_len(dest) <= 3 ? 0 : str_len(dest)-3);
		str_append(dest, "...");
	}
}

const char *str_sanitize(const char *src, size_t max_len)
{
	string_t *str;
	size_t i;

	if (src == NULL)
		return NULL;

	i = str_sanitize_skip_start(src, max_len);
	if (src[i] == '\0')
		return src;

	str = t_str_new(I_MIN(max_len, 256));
	str_append_n(str, src, i);
	str_sanitize_append(str, src + i, max_len - i);
	return str_c(str);
}
