#ifndef __MEMPOOL_H
#define __MEMPOOL_H

#include "macros.h"

/* Memory allocated and reallocated (the new data in it) in pools is always
   zeroed, it will cost only a few CPU cycles and may well save some debug
   time. */

typedef struct pool *pool_t;

struct pool {
	const char *(*get_name)(pool_t pool);

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
	unsigned int datastack_pool:1;
};

/* system_pool uses calloc() + realloc() + free() */
extern pool_t system_pool;

/* memory allocated from data_stack is valid only until next t_pop() call.
   No checks are performed. */
extern pool_t unsafe_data_stack_pool;

/* Create a new alloc-only pool. Note that `size' specifies the initial
   malloc()ed block size, part of it is used internally. */
pool_t pool_alloconly_create(const char *name, size_t size);

/* When allocating memory from returned pool, the data stack frame must be
   the same as it was when calling this function. pool_unref() also checks
   that the stack frame is the same. This should make it quite safe to use. */
pool_t pool_datastack_create(void);

/* Pools should be used through these macros: */
#define pool_get_name(pool) (pool)->get_name(pool)
#define pool_ref(pool) (pool)->ref(pool)
#define pool_unref(pool) (pool)->unref(pool)

#define p_new(pool, type, count) \
	((type *) p_malloc(pool, sizeof(type) * (count)))

#define p_malloc(pool, size) (pool)->malloc(pool, size)
#define p_realloc(pool, mem, old_size, new_size) \
	(pool)->realloc(pool, mem, old_size, new_size)
#define p_free(pool, mem) \
	STMT_START { \
          (pool)->free(pool, mem); \
          (mem) = NULL; \
	} STMT_END

#define p_clear(pool) (pool)->clear(pool)

#endif
