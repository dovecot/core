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

uint32_t i_rand_limit(uint32_t upper_bound)
{
	return arc4random_uniform(upper_bound);
}
#else
uint32_t i_rand(void)
{
	uint32_t value;
	random_fill(&value, sizeof(value));
	return value;
}

uint32_t i_rand_limit(uint32_t upper_bound)
{
	/* FIXME: This simple implementation suffers from modulo-bias. */
	return i_rand() % upper_bound;
}
#endif
