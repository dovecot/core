#ifndef __MEMPOOL_H
#define __MEMPOOL_H

#include "macros.h"

/* #define POOL_CHECK_LEAKS */

/* Memory allocated and reallocated (the new data in it) in pools is always
   zeroed, it will cost only a few CPU cycles and may well save some debug
   time. */

typedef struct pool *pool_t;

struct pool {
	void (*ref)(pool_t pool);
	void (*unref)(pool_t pool);

	void *(*malloc)(pool_t pool, size_t size);
	void (*free)(pool_t pool, void *mem);

	/* memory in old_size..new_size will be zeroed */
	void *(*realloc)(pool_t pool, void *mem,
			 size_t old_size, size_t new_size);

	/* Frees all the memory in pool. NOTE: system_pool doesn't support
	   this and crashes if it's used */
	void (*clear)(pool_t pool);

	unsigned int alloconly_pool:1;
};

/* system_pool uses calloc() + realloc() + free() */
extern pool_t system_pool;

/* memory allocated from data_stack is valid only until next t_pop() call. */
extern pool_t data_stack_pool;

/* Create a new alloc-only pool. Note that `size' specifies the initial
   malloc()ed block size, part of it is used internally. */
pool_t pool_alloconly_create(const char *name, size_t size);

/* Pools should be used through these macros: */
#define pool_ref(pool) (pool)->ref(pool)
#define pool_unref(pool) (pool)->unref(pool)

#define p_malloc(pool, size) (pool)->malloc(pool, size)
#define p_realloc(pool, mem, old_size, new_size) \
	(pool)->realloc(pool, mem, old_size, new_size)
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

#endif
