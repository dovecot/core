/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

/* @UNSAFE: whole file */

#include "lib.h"
#include "safe-memset.h"
#include "mempool.h"

/*
 * The system pool is a thin wrapper around calloc() and free().  It exists
 * to allow direct heap usage via the pool API.
 *
 * Implementation
 * ==============
 *
 * Creation
 * --------
 *
 * The system pool is created statically and therefore is available at any
 * time.
 *
 * Allocation, Reallocation & Freeing
 * ----------------------------------
 *
 * The p_malloc(), p_realloc(), and p_free() calls get directed to calloc(),
 * realloc(), and free().  There is no additional per-allocation information
 * to track.
 *
 * Clearing
 * --------
 *
 * Not supported.  Attempting to clear the system pool will result in a
 * panic.
 *
 * Destruction
 * -----------
 *
 * It is not possible to destroy the system pool.  Any attempt to unref the
 * pool is a no-op.
 */

#ifndef HAVE_MALLOC_USABLE_SIZE
/* no extra includes needed */
#elif defined (HAVE_MALLOC_NP_H)
#  include <malloc_np.h> /* FreeBSD */
#elif defined (HAVE_MALLOC_H)
#  include <malloc.h> /* Linux */
#endif

#define CLEAR_CHR 0xde

static const char *pool_system_get_name(pool_t pool);
static void pool_system_ref(pool_t pool);
static void pool_system_unref(pool_t *pool);
static void *pool_system_malloc(pool_t pool, size_t size);
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
#ifdef DEBUG
	int old_errno = errno;
#endif

	mem = calloc(size, 1);
	if (unlikely(mem == NULL)) {
		i_fatal_status(FATAL_OUTOFMEM, "pool_system_malloc(%"PRIuSIZE_T
			       "): Out of memory", size);
	}
#ifdef DEBUG
	/* we rely on errno not changing. it shouldn't. */
	i_assert(errno == old_errno);
#endif
	return mem;
}

void pool_system_free(pool_t pool ATTR_UNUSED, void *mem ATTR_UNUSED)
{
#ifdef DEBUG
	int old_errno = errno;
#endif
#if defined(HAVE_MALLOC_USABLE_SIZE) && defined(DEBUG)
	safe_memset(mem, CLEAR_CHR, malloc_usable_size(mem));
#endif
	free(mem);
#ifdef DEBUG
	/* we rely on errno not changing. it shouldn't. */
	i_assert(errno == old_errno);
#endif
}

static void *pool_system_realloc(pool_t pool ATTR_UNUSED, void *mem,
				 size_t old_size, size_t new_size)
{
	if (mem == NULL) {
		i_assert(old_size == 0);
		return pool_system_malloc(pool, new_size);
	}
#if defined(HAVE_MALLOC_USABLE_SIZE)
	i_assert(old_size == (size_t)-1 || mem == NULL ||
		 old_size <= malloc_usable_size(mem));
#endif

	mem = realloc(mem, new_size);
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
