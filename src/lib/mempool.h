#ifndef __MEMPOOL_H
#define __MEMPOOL_H

#include "macros.h"

/* #define POOL_CHECK_LEAKS */

/* Memory allocated and reallocated (the new data in it) in pools is always
   zeroed, it will cost only a few CPU cycles and may well save some debug
   time. */

typedef struct Pool *Pool;

struct Pool {
	void (*ref)(Pool pool);
	void (*unref)(Pool pool);

	void *(*malloc)(Pool pool, size_t size);
	void (*free)(Pool pool, void *mem);

	/* reallocate the `mem' to be exactly `size' */
	void *(*realloc)(Pool pool, void *mem, size_t size);
	/* reallocate the `mem' to be at least `size' if it wasn't previously */
	void *(*realloc_min)(Pool pool, void *mem, size_t size);

	/* Frees all the memory in pool. NOTE: system_pool doesn't support
	   this and crashes if it's used */
	void (*clear)(Pool pool);
};

/* system_pool uses calloc() + realloc() + free() */
extern Pool system_pool;

/* memory allocated from data_stack is valid only until next t_pop() call. */
extern Pool data_stack_pool;

/* If allocfree is FALSE, p_free() has no effect. Note that `size' specifies
   the initial malloc()ed block size, part of it is used internally. */
Pool pool_create(const char *name, size_t size, int allocfree);

/* Pools should be used through these macros: */
#define pool_ref(pool) (pool)->ref(pool)
#define pool_unref(pool) (pool)->unref(pool)

#define p_malloc(pool, size) (pool)->malloc(pool, size)
#define p_realloc(pool, mem, size) (pool)->realloc(pool, mem, size)
#define p_realloc_min(pool, mem, size) (pool)->realloc_min(pool, mem, size)
#define p_free(pool, mem) (pool)->free(pool, mem)

#define p_clear(pool) (pool)->clear(pool)

/* Extra macros to make life easier: */
#define p_new(pool, type, count) \
	((type *) p_malloc(pool, sizeof(type) * (count)))
#define p_free_and_null(pool, rec) \
	STMT_START { \
          p_free(pool, rec); \
          (rec) = NULL; \
	} STMT_END

/* p_free_clean() should be used when pool is being destroyed, so freeing
   memory isn't needed for anything else than detecting memory leaks. */
#ifdef POOL_CHECK_LEAKS
#  define p_free_clean(pool, mem) p_free(pool, mem)
#else
#  define p_free_clean(pool, mem)
#endif

Pool _pool_alloconly_create(const char *name, size_t size);

#endif
