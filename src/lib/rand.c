/* Copyright (c) 2014-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "randgen.h"

#ifdef HAVE_ARC4RANDOM
#ifdef HAVE_LIBBSD
#include <bsd/stdlib.h>
#endif

uint32_t i_rand(void)
{
	return arc4random();
}
#else
uint32_t i_rand(void)
{
	uint32_t value;
	random_fill(&value, sizeof(value));
	return value;
}
#endif
