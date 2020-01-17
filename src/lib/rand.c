/* Copyright (c) 2014-2018 Dovecot authors, see the included COPYING file */

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
	i_assert(upper_bound > 0);

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
	i_assert(upper_bound > 0);

	uint32_t val, min = -upper_bound % upper_bound;
	while((val = i_rand()) < min);
	return val % upper_bound;
}
#endif
