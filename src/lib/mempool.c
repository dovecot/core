/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"

/* The various implementations of pools API assume that they'll never be
   asked for more than SSIZE_T_MAX bytes.  This is a sanity check to make
   sure nobody accidentally bumped the define beyond what's expected. */
#if POOL_MAX_ALLOC_SIZE > SSIZE_T_MAX
#error "POOL_MAX_ALLOC_SIZE is too large"
#endif

size_t pool_get_exp_grown_size(pool_t pool, size_t old_size, size_t min_size)
{
	size_t exp_size, easy_size;

	i_assert(old_size < min_size);

	exp_size = nearest_power(min_size);
	easy_size = old_size + p_get_max_easy_alloc_size(pool);

	if (easy_size < exp_size && easy_size >= min_size)
		exp_size = easy_size;
	i_assert(exp_size >= min_size);
	return exp_size;
}
