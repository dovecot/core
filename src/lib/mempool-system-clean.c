/* Copyright (c) 2007-2009 Dovecot authors, see the included COPYING file */

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

/* use the maximum of required memory alignment and sizeof(void *)
   (sizeof(size_t) is assumed to be same. it always is.) */
#if MEM_ALIGN_SIZE > SIZEOF_VOID_P
#  define EXTRA_SIZE_SPACE MEM_ALIGN_SIZE
#else
#  define EXTRA_SIZE_SPACE SIZEOF_VOID_P
#endif

/* FIXME: Disabled for now, broken with Valgrind and HP-UX. */
#undef HAVE_MALLOC_USABLE_SIZE

static const char *pool_system_clean_get_name(pool_t pool);
static void pool_system_clean_ref(pool_t pool);
static void pool_system_clean_unref(pool_t *pool);
static void *pool_system_clean_malloc(pool_t pool, size_t size);
static void pool_system_clean_free(pool_t pool, void *mem);
static void *pool_system_clean_realloc(pool_t pool, void *mem,
				       size_t old_size, size_t new_size);
static void pool_system_clean_clear(pool_t pool);
static size_t pool_system_clean_get_max_easy_alloc_size(pool_t pool);

static struct pool_vfuncs static_system_clean_pool_vfuncs = {
	pool_system_clean_get_name,

	pool_system_clean_ref,
	pool_system_clean_unref,

	pool_system_clean_malloc,
	pool_system_clean_free,

	pool_system_clean_realloc,

	pool_system_clean_clear,
	pool_system_clean_get_max_easy_alloc_size
};

static struct pool static_system_clean_pool = {
	.v = &static_system_clean_pool_vfuncs,

	.alloconly_pool = FALSE,
	.datastack_pool = FALSE
};

pool_t system_clean_pool = &static_system_clean_pool;

static const char *pool_system_clean_get_name(pool_t pool ATTR_UNUSED)
{
	return "system clean";
}

static void pool_system_clean_ref(pool_t pool ATTR_UNUSED)
{
}

static void pool_system_clean_unref(pool_t *pool ATTR_UNUSED)
{
}

static size_t mem_get_size(void *mem)
{
#ifdef USE_GC
	return GC_size(mem);
#elif defined(HAVE_MALLOC_USABLE_SIZE)
	return malloc_usable_size(mem);
#else
	return *((size_t *)PTR_OFFSET(mem, -EXTRA_SIZE_SPACE));
#endif
}

static void *pool_system_clean_malloc(pool_t pool ATTR_UNUSED, size_t size)
{
	void *mem;

	if (unlikely(size == 0 || size > SSIZE_T_MAX))
		i_panic("Trying to allocate %"PRIuSIZE_T" bytes", size);

#ifdef USE_GC
	mem = GC_malloc(size);
#else
#ifndef HAVE_MALLOC_USABLE_SIZE
	size += EXTRA_SIZE_SPACE;
#endif
	mem = calloc(size, 1);
#endif
	if (unlikely(mem == NULL)) {
		i_fatal_status(FATAL_OUTOFMEM, "pool_system_malloc(%"PRIuSIZE_T
			       "): Out of memory", size);
	}
#if !defined(USE_GC) && !defined(HAVE_MALLOC_USABLE_SIZE)
	{
		size_t *saved_size = mem;

		*saved_size = size - EXTRA_SIZE_SPACE;
		mem = PTR_OFFSET(mem, EXTRA_SIZE_SPACE);
	}
#endif
	return mem;
}

static void pool_system_clean_free(pool_t pool ATTR_UNUSED, void *mem)
{
	if (mem != NULL) {
		safe_memset(mem, 0, mem_get_size(mem));
#ifndef USE_GC
#ifndef HAVE_MALLOC_USABLE_SIZE
		mem = PTR_OFFSET(mem, -EXTRA_SIZE_SPACE);
#endif
		free(mem);
#endif
	}
}

static void *pool_system_clean_realloc(pool_t pool ATTR_UNUSED, void *mem,
				       size_t old_size, size_t new_size)
{
	void *new_mem;
	size_t old_alloc_size;

	if (unlikely(new_size == 0 || new_size > SSIZE_T_MAX))
		i_panic("Trying to allocate %"PRIuSIZE_T" bytes", new_size);

	new_mem = pool_system_clean_malloc(pool, new_size);
	if (mem != NULL) {
#if !defined(USE_GC) && defined(HAVE_MALLOC_USABLE_SIZE)
		i_assert(old_size == (size_t)-1 ||
			 old_size <= malloc_usable_size(mem));
#endif
		old_alloc_size = mem_get_size(mem);
		memcpy(new_mem, mem, I_MIN(old_alloc_size, new_size));

		if (old_size < new_size) {
			/* clear new data */
			memset((char *)new_mem + old_size, 0,
			       new_size - old_size);
		}
		pool_system_clean_free(pool, mem);
	}

        return new_mem;
}

static void ATTR_NORETURN
pool_system_clean_clear(pool_t pool ATTR_UNUSED)
{
	i_panic("pool_system_clean_clear() must not be called");
}

static size_t
pool_system_clean_get_max_easy_alloc_size(pool_t pool ATTR_UNUSED)
{
	return 0;
}
