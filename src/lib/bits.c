/* Copyright (c) 2001-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"

/*
 * We could use bits_required64() unconditionally, but that's unnecessary
 * and way more heavy weight on 32-bit systems.
 */
#ifdef _LP64
#define BITS_REQUIRED(x)	bits_required64(x)
#else
#define BITS_REQUIRED(x)	bits_required32(x)
#endif

size_t nearest_power(size_t num)
{
	i_assert(num <= ((size_t)1 << (CHAR_BIT*sizeof(size_t) - 1)));

	if (num == 0)
		return 1;

	return 1UL << BITS_REQUIRED(num - 1);
}

#if __GNUC__ > 3 || (__GNUC__ == 3 && __GNUC_MINOR__ >= 4)
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
