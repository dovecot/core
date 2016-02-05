/* Copyright (c) 2001-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"

size_t nearest_power(size_t num)
{
	size_t n = 1;

	i_assert(num <= ((size_t)1 << (CHAR_BIT*sizeof(size_t) - 1)));

	while (n < num) n <<= 1;
	return n;
}

#if __GNUC__ > 2
/* Lucky you, it's all inline intrinsics */
#else
unsigned int bits_required8(uint8_t num)
{
	int ret = 0;
	if (num > 0xf) { ret += 4; num >>= 4; }
	if (num > 0x3) { ret += 2; num >>= 2; }
	num &= ~(num>>1); /* 3->2, else unchanged */
	return ret + num;
}
#endif
