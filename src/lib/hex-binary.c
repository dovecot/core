/*
 hex-binary.c : hex translations

    Copyright (c) 2002 Timo Sirainen

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
#include "buffer.h"
#include "hex-binary.h"

const char *binary_to_hex(const unsigned char *data, size_t size)
{
	char *buf, *p;
	size_t i;
	int value;

	/* @UNSAFE */

	buf = p = t_malloc(size * 2 + 1);
	for (i = 0; i < size; i++) {
		value = data[i] >> 4;
		*p++ = value < 10 ? value + '0' : value - 10 + 'a';

		value = data[i] & 0x0f;
		*p++ = value < 10 ? value + '0' : value - 10 + 'a';
	}

	*p = '\0';
	return buf;
}

int hex_to_binary(const char *data, Buffer *dest)
{
	int value;

	while (*data != '\0') {
		if (*data >= '0' && *data <= '9')
			value = (*data - '0') << 4;
		else if (*data >= 'a' && *data <= 'f')
			value = (*data - 'a' + 10) << 4;
		else if (*data >= 'A' && *data <= 'F')
			value = (*data - 'A' + 10) << 4;
		else
			return -1;

		data++;
		if (*data >= '0' && *data <= '9')
			value |= *data - '0';
		else if (*data >= 'a' && *data <= 'f')
			value |= *data - 'a' + 10;
		else if (*data >= 'A' && *data <= 'F')
			value |= *data - 'A' + 10;
		else
			return -1;

		if (buffer_append_c(dest, value) != 1)
			return 0;
		data++;
	}

	return 1;
}
