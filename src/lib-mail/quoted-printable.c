/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "hex-binary.h"
#include "quoted-printable.h"

size_t quoted_printable_decode(const unsigned char *src, size_t *size,
			       unsigned char *dest)
{
	const unsigned char *end;
	unsigned char *dest_start;
	char hexbuf[3];

	hexbuf[2] = '\0';

	dest_start = dest;
	end = src + *size;

	for (; src != end; src++) {
		if (*src == '_') {
			*dest++ = ' ';
			continue;
		}

		if (*src == '=') {
			if (src+2 >= end)
				break;

			hexbuf[0] = src[1];
			hexbuf[1] = src[2];

			if (hex_to_binary(hexbuf, dest) == 1) {
				dest++;
				src += 2;
				continue;
			}
		}

		*dest++ = *src;
	}

	*size -= (end-src);
	return (size_t) (dest - dest_start);
}
