/* Copyright (c) 2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "numpack.h"

void numpack_encode(buffer_t *buf, uint64_t num)
{
	/* number continues as long as the highest bit is set */
	while (num >= 0x80) {
		buffer_append_c(buf, (num & 0x7f) | 0x80);
		num >>= 7;
	}

	buffer_append_c(buf, num);
}

int numpack_decode(const uint8_t **p, const uint8_t *end, uint64_t *num_r)
{
	const uint8_t *c = *p;
	uint64_t value = 0;
	unsigned int bits = 0;

	for (;;) {
		if (c == end)
			return -1;

		value |= (uint64_t)(*c & 0x7f) << bits;
		if (*c < 0x80)
			break;

		bits += 7;
		c++;
	}

	if (bits >= 64) {
		/* overflow */
		*p = end;
		return -1;
	}

	*p = c + 1;
	*num_r = value;
	return 0;
}
