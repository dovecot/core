/* Copyright (c) 2005-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"

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
