/* Copyright (c) 2014-2016 Dovecot authors, see the included COPYING file */

/* Wrap srand() so that we can reproduce fuzzed tests */

#include "lib.h"

static int seeded = 0;
static unsigned int seed;
static char const *env_seed;

int rand_get_seed_count(void)
{
	return seeded;
}
unsigned int rand_get_last_seed(void)
{
	i_assert(seeded > 0);
	return seed;
}
void rand_set_seed(unsigned int s)
{
	if (seeded == 0) {
		unsigned int seedval;
		env_seed = getenv("DOVECOT_SRAND");
		if (env_seed != NULL && str_to_uint(env_seed, &seedval) >= 0)
			seed = seedval;
	}
	seeded++;
	if (env_seed == NULL)
		seed = s;

	srand(seed);
}

#ifdef HAVE_ARC4RANDOM
#ifdef HAVE_LIBBSD
#include <bsd/stdlib.h>
#endif

/* this returns [0,RAND_MAX), to keep it compatible with rand() */
int arc4random_rand(void) {
	return (int)(arc4random() % ((unsigned)RAND_MAX + 1));
}
#endif
