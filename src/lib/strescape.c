/*
    Copyright (c) 2003 Timo Sirainen

    Permission is hereby granted, free of charge, to any person obtaining
    a copy of this software and associated documentation files (the
    "Software"), to deal in the Software without restriction, including
    without limitation the rights to use, copy, modify, merge, publish,
    distribute, sublicense, and/or sell copies of the Software, and to
    permit persons to whom the Software is furnished to do so, subject to
    the following conditions:

    The above copyright notice and this permission notice shall be
    included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
    OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
    MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
    IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
    CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
    TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
    SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

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
		start = i;
		for (; i < src_size; i++) {
			if (src_c[i] == '\\')
				break;
		}

		str_append_n(dest, src_c + start, i-start);

		if (i < src_size)
			i++;
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
		if (*str == '\\' && str[1] != '\0')
			str++;

		*dest++ = *str;
	}

	*dest = '\0';
	return start;
}
