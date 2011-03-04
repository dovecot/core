/* Copyright (c) 2003-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "strescape.h"

const char *str_escape(const char *str)
{
	const char *p;
	string_t *ret;

	/* see if we need to quote it */
	for (p = str; *p != '\0'; p++) {
		if (IS_ESCAPED_CHAR(*p))
			break;
	}

	if (*p == '\0')
		return str;

	/* quote */
	ret = t_str_new((size_t) (p - str) + 128);
	str_append_n(ret, str, (size_t) (p - str));

	for (; *p != '\0'; p++) {
		if (IS_ESCAPED_CHAR(*p))
			str_append_c(ret, '\\');
		str_append_c(ret, *p);
	}
	return str_c(ret);
}

void str_append_unescaped(string_t *dest, const void *src, size_t src_size)
{
	const unsigned char *src_c = src;
	size_t start = 0, i = 0;

	while (i < src_size) {
		for (; i < src_size; i++) {
			if (src_c[i] == '\\')
				break;
		}

		str_append_n(dest, src_c + start, i-start);

		if (i < src_size) {
			if (++i == src_size)
				break;
			str_append_c(dest, src_c[i++]);
		}
		start = i;
	}
}

char *str_unescape(char *str)
{
	/* @UNSAFE */
	char *dest, *start = str;

	while (*str != '\\') {
		if (*str == '\0')
			return start;
		str++;
	}

	for (dest = str; *str != '\0'; str++) {
		if (*str == '\\') {
			str++;
			if (*str == '\0')
				break;
		}

		*dest++ = *str;
	}

	*dest = '\0';
	return start;
}

void str_tabescape_write(string_t *dest, const char *src)
{
	for (; *src != '\0'; src++) {
		switch (*src) {
		case '\001':
			str_append_c(dest, '\001');
			str_append_c(dest, '1');
			break;
		case '\t':
			str_append_c(dest, '\001');
			str_append_c(dest, 't');
			break;
		case '\r':
			str_append_c(dest, '\001');
			str_append_c(dest, 'r');
			break;
		case '\n':
			str_append_c(dest, '\001');
			str_append_c(dest, 'n');
			break;
		default:
			str_append_c(dest, *src);
			break;
		}
	}
}

const char *str_tabescape(const char *str)
{
	string_t *tmp;
	const char *p;

	for (p = str; *p != '\0'; p++) {
		if (*p <= '\r') {
			tmp = t_str_new(128);
			str_append_n(tmp, str, p-str);
			str_tabescape_write(tmp, p);
			return str_c(tmp);
		}
	}
	return str;
}

void str_append_tabunescaped(string_t *dest, const void *src, size_t src_size)
{
	const unsigned char *src_c = src;
	size_t start = 0, i = 0;

	while (i < src_size) {
		for (; i < src_size; i++) {
			if (src_c[i] == '\001')
				break;
		}

		str_append_n(dest, src_c + start, i-start);

		if (i < src_size) {
			i++;
			if (i < src_size) {
				switch (src_c[i]) {
				case '1':
					str_append_c(dest, '\001');
					break;
				case 't':
					str_append_c(dest, '\t');
					break;
				case 'r':
					str_append_c(dest, '\r');
					break;
				case 'n':
					str_append_c(dest, '\n');
					break;
				default:
					str_append_c(dest, src_c[i]);
					break;
				}
				i++;
			}
		}
		start = i;
	}
}

char *str_tabunescape(char *str)
{
	/* @UNSAFE */
	char *dest, *start = str;

	while (*str != '\001') {
		if (*str == '\0')
			return start;
		str++;
	}

	for (dest = str; *str != '\0'; str++) {
		if (*str != '\001')
			*dest++ = *str;
		else {
			str++;
			if (*str == '\0')
				break;
			switch (*str) {
			case '1':
				*dest++ = '\001';
				break;
			case 't':
				*dest++ = '\t';
				break;
			case 'r':
				*dest++ = '\r';
				break;
			case 'n':
				*dest++ = '\n';
				break;
			default:
				*dest++ = *str;
				break;
			}
		}
	}

	*dest = '\0';
	return start;
}
