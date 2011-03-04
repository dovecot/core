/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

/* @UNSAFE: whole file */

#include "lib.h"
#include "safe-memset.h"
#include "mempool.h"

#include <stdlib.h>
#ifndef HAVE_MALLOC_USABLE_SIZE
/* no extra includes needed */
#elif defined (HAVE_MALLOC_NP_H)
#  include <malloc_np.h> /* FreeBSD */
#elif defined (HAVE_MALLOC_H)
#  include <malloc.h> /* Linux */
#endif

#ifdef HAVE_GC_GC_H
#  include <gc/gc.h>
#elif defined (HAVE_GC_H)
#  include <gc.h>
#endif

#define CLEAR_CHR 0xde

static const char *pool_system_get_name(pool_t pool);
static void pool_system_ref(pool_t pool);
static void pool_system_unref(pool_t *pool);
static void *pool_system_malloc(pool_t pool, size_t size);
static void pool_system_free(pool_t pool, void *mem);
static void *pool_system_realloc(pool_t pool, void *mem,
				 size_t old_size, size_t new_size);
static void pool_system_clear(pool_t pool);
static size_t pool_system_get_max_easy_alloc_size(pool_t pool);

static struct pool_vfuncs static_system_pool_vfuncs = {
	pool_system_get_name,

	pool_system_ref,
	pool_system_unref,

	pool_system_malloc,
	pool_system_free,

	pool_system_realloc,

	pool_system_clear,
	pool_system_get_max_easy_alloc_size
};

struct pool static_system_pool = {
	.v = &static_system_pool_vfuncs,

	.alloconly_pool = FALSE,
	.datastack_pool = FALSE
};

pool_t system_pool = &static_system_pool;

static const char *pool_system_get_name(pool_t pool ATTR_UNUSED)
{
	return "system";
}

static void pool_system_ref(pool_t pool ATTR_UNUSED)
{
}

static void pool_system_unref(pool_t *pool ATTR_UNUSED)
{
}

static void *pool_system_malloc(pool_t pool ATTR_UNUSED, size_t size)
{
	void *mem;

	if (unlikely(size == 0 || size > SSIZE_T_MAX))
		i_panic("Trying to allocate %"PRIuSIZE_T" bytes", size);

#ifndef USE_GC
	mem = calloc(size, 1);
#else
	mem = GC_malloc(size);
#endif
	if (unlikely(mem == NULL)) {
		i_fatal_status(FATAL_OUTOFMEM, "pool_system_malloc(%"PRIuSIZE_T
			       "): Out of memory", size);
	}
	return mem;
}

static void pool_system_free(pool_t pool ATTR_UNUSED,
			     void *mem ATTR_UNUSED)
{
#if !defined(USE_GC) && defined(HAVE_MALLOC_USABLE_SIZE) && defined(DEBUG)
	safe_memset(mem, CLEAR_CHR, malloc_usable_size(mem));
#endif
#ifndef USE_GC
	free(mem);
#endif
}

static void *pool_system_realloc(pool_t pool ATTR_UNUSED, void *mem,
				 size_t old_size, size_t new_size)
{
	if (unlikely(new_size == 0 || new_size > SSIZE_T_MAX))
		i_panic("Trying to allocate %"PRIuSIZE_T" bytes", new_size);

#if !defined(USE_GC) && defined(HAVE_MALLOC_USABLE_SIZE)
	i_assert(old_size == (size_t)-1 || mem == NULL ||
		 old_size <= malloc_usable_size(mem));
#endif

#ifndef USE_GC
	mem = realloc(mem, new_size);
#else
	mem = GC_realloc(mem, new_size);
#endif
	if (unlikely(mem == NULL)) {
		i_fatal_status(FATAL_OUTOFMEM, "pool_system_realloc(%"PRIuSIZE_T
			       "): Out of memory", new_size);
	}

	if (old_size < new_size) {
                /* clear new data */
		memset((char *) mem + old_size, 0, new_size - old_size);
	}

        return mem;
}

static void ATTR_NORETURN
pool_system_clear(pool_t pool ATTR_UNUSED)
{
	i_panic("pool_system_clear() must not be called");
}

static size_t pool_system_get_max_easy_alloc_size(pool_t pool ATTR_UNUSED)
{
	return 0;
}
