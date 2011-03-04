/* Copyright (c) 2004-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "unichar.h"
#include "str.h"
#include "str-sanitize.h"

static size_t str_sanitize_skip_start(const char *src, size_t max_len)
{
	unsigned int len;
	unichar_t chr;
	size_t i;

	for (i = 0; i < max_len; ) {
		len = uni_utf8_char_bytes(src[i]);
		if (uni_utf8_get_char(src+i, &chr) <= 0)
			break;
		if ((unsigned char)src[i] < 32)
			break;
		i += len;
	}
	return i;
}

void str_sanitize_append(string_t *dest, const char *src, size_t max_len)
{
	unsigned int len;
	unichar_t chr;
	size_t i;
	int ret;

	for (i = 0; i < max_len && src[i] != '\0'; ) {
		len = uni_utf8_char_bytes(src[i]);
		ret = uni_utf8_get_char(src+i, &chr);
		if (ret <= 0) {
			/* invalid UTF-8 */
			str_append_c(dest, '?');
			if (ret == 0) {
				/* input ended too early */
				return;
			}
			i++;
			continue;
		}
		if ((unsigned char)src[i] < 32)
			str_append_c(dest, '?');
		else
			str_append_c(dest, src[i]);
		i += len;
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
