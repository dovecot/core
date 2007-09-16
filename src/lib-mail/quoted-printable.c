/* Copyright (c) 2002-2007 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "hex-binary.h"
#include "quoted-printable.h"

void quoted_printable_decode(const unsigned char *src, size_t src_size,
			     size_t *src_pos_r, buffer_t *dest)
{
	char hexbuf[3];
	size_t src_pos, next;

	hexbuf[2] = '\0';

	next = 0;
	for (src_pos = 0; src_pos < src_size; src_pos++) {
		if (src[src_pos] != '_' && src[src_pos] != '=')
			continue;

		buffer_append(dest, src + next, src_pos - next);
		next = src_pos+1;

		if (src[src_pos] == '_') {
			buffer_append_c(dest, ' ');
			continue;
		}

		if (src_pos+1 >= src_size)
			break;

		if (src[src_pos+1] == '\n') {
			/* =\n -> skip both */
			src_pos++;
			continue;
		}

		if (src_pos+2 >= src_size)
			break;

		if (src[src_pos+1] == '\r' && src[src_pos+2] == '\n') {
			/* =\r\n -> skip both */
			src_pos += 2;
			next++;
			continue;
		}

		/* =<hex> */
		hexbuf[0] = src[src_pos+1];
		hexbuf[1] = src[src_pos+2];

		if (hex_to_binary(hexbuf, dest) == 0) {
			src_pos += 2;
			next = src_pos+1;
		} else {
			/* non-hex data, show as-is */
			next = src_pos;
		}
	}

	buffer_append(dest, src + next, src_size - next);

	if (src_pos_r != NULL)
		*src_pos_r = src_pos;
}
