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

/*
 * The following generates a random number in the range [0, upper_bound)
 * with each possible value having equal probability of occurring.
 *
 * This algorithm is not original, but it is dense enough that a detailed
 * explanation is in order.
 *
 * The big problem is that we want a uniformly random values.  If one were
 * to do `i_rand() % upper_bound`, the result probability distribution would
 * depend on the value of the upper bound.  When the upper bound is a power
 * of 2, the distribution is uniform.  If it is not a power of 2, the
 * distribution is skewed.
 *
 * The naive modulo approach breaks down because the division effectively
 * splits the whole range of input values into a number of fixed sized
 * "buckets", but with non-power-of-2 bound the last bucket is not the full
 * size.
 *
 * To fix this bias, we reduce the input range such that the remaining
 * values can be split exactly into equal sized buckets.
 *
 * For example, let's assume that i_rand() produces a uint8_t to simplify
 * the math, and that we want a random number [0, 9] - in other words,
 * upper_bound == 10.
 *
 * `i_rand() % 10` makes buckets 10 numbers wide, but the last bucket is only
 * 6 numbers wide (250..255).  Therefore, 0..5 will occur more frequently
 * than 6..9.
 *
 * If we reduce the input range to [0, 250), the result of the mod 10 will
 * be uniform.  Interestingly, the same can be accomplished if we reduce the
 * input range to [6, 255].
 *
 * This minimum value can be calculated as: 256 % 10 = 6.
 *
 * Or more generically: (UINT32_MAX + 1) % upper_bound.
 *
 * Then, we can pick random numbers until we get one that is >= this
 * minimum.  Once we have it, we can simply mod it by the limit to get our
 * answer.
 *
 * For our example of modding by 10, we pick random numbers until they are
 * greater than or equal to 6.  Once we have one, we have a value in the
 * range [6, 255] which when modded by 10 yields uniformly distributed
 * values [0, 9].
 *
 * There are two things to consider while implementing this algorithm:
 *
 * 1. Division by 0: Getting called with a 0 upper bound doesn't make sense,
 *    therefore we simply assert that the passed in bound is non-zero.
 *
 * 2. 32-bit performance: The above expression to calculate the minimum
 *    value requires 64-bit division.  This generally isn't a problem on
 *    64-bit systems, but 32-bit systems often end up calling a software
 *    implementation (e.g., `__umoddi3`).  This is undesirable.
 *
 *    Therefore, we rewrite the expression as:
 *
 *    ~(upper_bound - 1) % upper_bound
 *
 *    This is harder to understand, but it is 100% equivalent.
 */
uint32_t i_rand_limit(uint32_t upper_bound)
{
	i_assert(upper_bound > 0);

	uint32_t val;
	uint32_t min = UNSIGNED_MINUS(upper_bound) % upper_bound;
	while((val = i_rand()) < min);
	return val % upper_bound;
}
#endif
