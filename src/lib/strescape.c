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
	char *ret, *p;
	size_t i, esc;

	/* get length of string and number of chars to escape */
	esc = 0;
	for (i = 0; str[i] != '\0'; i++) {
		if (IS_ESCAPED_CHAR(str[i]))
			esc++;
	}

	if (esc == 0)
		return str;

	/* @UNSAFE: escape them */
	p = ret = t_malloc(i + esc + 1);
	for (; *str != '\0'; str++) {
		if (IS_ESCAPED_CHAR(*str))
			*p++ = '\\';
		*p++ = *str;
	}
	*p = '\0';
	return ret;
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

		if (src_c[i] == '\\')
			i++;
		start = i;
	}
}

void str_unescape(char *str)
{
	/* @UNSAFE */
	char *dest;

	while (*str != '\\') {
		if (*str == '\0')
			return;
		str++;
	}

	for (dest = str; *str != '\0'; str++) {
		if (*str != '\\' || str[1] == '\0')
			*dest++ = *str;
	}

	*dest = '\0';
}
