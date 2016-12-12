/* Copyright (c) 2004-2016 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "unichar.h"
#include "str.h"
#include "str-sanitize.h"

static size_t str_sanitize_skip_start(const char *src, size_t max_bytes)
{
	unichar_t chr;
	size_t i;

	for (i = 0; i < max_bytes && src[i] != '\0'; ) {
		int len = uni_utf8_get_char_n(src+i, max_bytes-i, &chr);
		if (len <= 0)
			break;
		if ((unsigned char)src[i] < 32)
			break;
		i += len;
	}
	i_assert(i <= max_bytes);
	return i;
}

static void str_sanitize_truncate_char(string_t *dest, unsigned int initial_pos)
{
	const unsigned char *data = str_data(dest);
	size_t len = str_len(dest);

	if (len == initial_pos)
		return;
	if ((data[len-1] & 0x80) == 0) {
		str_truncate(dest, len-1);
		return;
	}
	/* truncate UTF-8 sequence. */
	while (len > 0 && (data[len-1] & 0xc0) == 0x80)
		len--;
	if (len > 0 && (data[len-1] & 0xc0) == 0xc0)
		len--;
	if (len >= initial_pos)
		str_truncate(dest, len);
}

void str_sanitize_append(string_t *dest, const char *src, size_t max_bytes)
{
	size_t initial_pos = str_len(dest);
	unichar_t chr;
	size_t i;

	for (i = 0; i < max_bytes && src[i] != '\0'; ) {
		int len = uni_utf8_get_char_n(src+i, max_bytes-i, &chr);
		if (len == 0)
			break; /* input ended too early */

		if (len < 0) {
			/* invalid UTF-8 */
			str_append_c(dest, '?');
			i++;
			continue;
		}
		if ((unsigned char)src[i] < 32)
			str_append_c(dest, '?');
		else
			str_append_n(dest, src+i, len);
		i += len;
	}

	if (src[i] != '\0') {
		if (max_bytes < 3)
			str_truncate(dest, initial_pos);
		else {
			while (str_len(dest) - initial_pos > max_bytes-3)
				str_sanitize_truncate_char(dest, initial_pos);
		}
		str_append(dest, "...");
	}
}

const char *str_sanitize(const char *src, size_t max_bytes)
{
	string_t *str;
	size_t i;

	if (src == NULL)
		return NULL;

	i = str_sanitize_skip_start(src, max_bytes);
	if (src[i] == '\0')
		return src;

	str = t_str_new(I_MIN(max_bytes, 256));
	str_sanitize_append(str, src, max_bytes);
	return str_c(str);
}
