/* Copyright (c) 2023 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "mempool.h"

static const char *pool_null_get_name(pool_t pool ATTR_UNUSED)
{
	return "null pool";
}

static void pool_null_ref(pool_t pool)
{
	i_assert(pool == null_pool);
}

static void pool_null_unref(pool_t *pool)
{
	i_assert(*pool == null_pool);
}

static void *pool_null_malloc(pool_t pool ATTR_UNUSED, size_t size ATTR_UNUSED)
{
	i_panic("null pool: malloc() called");
}

static void pool_null_free(pool_t pool ATTR_UNUSED, void *mem ATTR_UNUSED)
{
}

static void *
pool_null_realloc(pool_t pool ATTR_UNUSED, void *mem ATTR_UNUSED,
		  size_t old_size ATTR_UNUSED, size_t new_size ATTR_UNUSED)
{
	i_panic("null pool: realloc() called");
}

static void pool_null_clear(pool_t pool)
{
	i_assert(pool == null_pool);
}

static size_t
pool_null_get_max_easy_alloc_size(pool_t pool ATTR_UNUSED)
{
	return 0;
}

static struct pool_vfuncs static_null_pool_vfuncs = {
	pool_null_get_name,

	pool_null_ref,
	pool_null_unref,

	pool_null_malloc,
	pool_null_free,

	pool_null_realloc,

	pool_null_clear,
	pool_null_get_max_easy_alloc_size
};

static struct pool static_null_pool = {
	.v = &static_null_pool_vfuncs,
};

pool_t null_pool = &static_null_pool;
