/* Copyright (C) 2003 Timo Sirainen */

#include "lib.h"
#include "byteorder.h"

#ifndef WORDS_BIGENDIAN

#define swap64(num) \
	(((num & 0x00000000000000ffULL) << 56) | \
	 ((num & 0x000000000000ff00ULL) << 40) | \
	 ((num & 0x0000000000ff0000ULL) << 24) | \
	 ((num & 0x00000000ff000000ULL) <<  8) | \
	 ((num & 0x000000ff00000000ULL) >>  8) | \
	 ((num & 0x0000ff0000000000ULL) >> 24) | \
	 ((num & 0x00ff000000000000ULL) >> 40) | \
	 ((num & 0xff00000000000000ULL) >> 56))


uint64_t nbo_to_uint64(uint64_t num)
{
	return swap64(num);
}

uint64_t uint64_to_nbo(uint64_t num)
{
	return swap64(num);
}
#endif
