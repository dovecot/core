/* Copyright (c) 2004 Timo Sirainen */

#include "lib.h"
#include "str.h"
#include "str-sanitize.h"

void str_sanitize_append(string_t *dest, const char *src, size_t max_len)
{
	const char *p;

	for (p = src; *p != '\0'; p++) {
		if (((unsigned char)*p & 0x7f) < 32)
			break;
	}

	str_append_n(dest, src, (size_t)(p - src));
	for (; *p != '\0' && max_len > 0; p++, max_len--) {
		if (((unsigned char)*p & 0x7f) < 32)
			str_append_c(dest, '?');
		else
			str_append_c(dest, *p);
	}

	if (*p != '\0') {
		str_truncate(dest, str_len(dest)-3);
		str_append(dest, "...");
	}
}

const char *str_sanitize(const char *src, size_t max_len)
{
	string_t *str;

	str = t_str_new(I_MIN(max_len, 256));
	str_sanitize_append(str, src, max_len);
	return str_c(str);
}
