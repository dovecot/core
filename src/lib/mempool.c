/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"

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

void pool_add_external_ref(pool_t pool, pool_t ref_pool)
{
	i_assert(pool != system_pool);
	i_assert(ref_pool != system_pool);
	i_assert(!pool->datastack_pool);
	i_assert(!ref_pool->datastack_pool);

	if (!array_is_created(&pool->external_refs))
		i_array_init(&pool->external_refs, 1);
	array_push_back(&pool->external_refs, &ref_pool);
	pool_ref(ref_pool);
}

void pool_external_refs_unref(pool_t pool)
{
	if (array_is_created(&pool->external_refs)) {
		pool_t external_pool;
		array_foreach_elem(&pool->external_refs, external_pool)
			pool_unref(&external_pool);
		array_free(&pool->external_refs);
	}
}
