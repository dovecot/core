#ifndef MEMPOOL_H
#define MEMPOOL_H

#include "macros.h"

/* When DEBUG is enabled, Dovecot warns whenever a memory pool is grown.
   This is done so that the initial pool size could be set large enough so that
   it wouldn't grow in normal use. For some memory pools it's too difficult
   to calculate a good initial size, so this prefix should be used with those
   pools to disable the warning. */
#define MEMPOOL_GROWING "GROWING-"

/* Memory allocated and reallocated (the new data in it) in pools is always
   zeroed, it will cost only a few CPU cycles and may well save some debug
   time. */

typedef struct pool *pool_t;

struct pool_vfuncs {
	const char *(*get_name)(pool_t pool);

	void (*ref)(pool_t pool);
	void (*unref)(pool_t *pool);

	void *(*malloc)(pool_t pool, size_t size);
	void (*free)(pool_t pool, void *mem);

	/* memory in old_size..new_size will be zeroed */
	void *(*realloc)(pool_t pool, void *mem,
			 size_t old_size, size_t new_size)
		ATTR_WARN_UNUSED_RESULT;

	/* Frees all the memory in pool. NOTE: system_pool doesn't support
	   this and crashes if it's used */
	void (*clear)(pool_t pool);

	/* Returns the maximum amount of bytes that can be allocated with
	   minimal trouble. If there's no such concept, always returns 0. */
	size_t (*get_max_easy_alloc_size)(pool_t pool);
};

struct pool {
	const struct pool_vfuncs *v;

	unsigned int alloconly_pool:1;
	unsigned int datastack_pool:1;
};

/* system_pool uses calloc() + realloc() + free() */
extern pool_t system_pool;
extern struct pool static_system_pool;

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

/* Similar to nearest_power(), but try not to exceed buffer's easy
   allocation size. If you don't have any explicit minimum size, use
   old_size + 1. */
size_t pool_get_exp_grown_size(pool_t pool, size_t old_size, size_t min_size);

/* Pools should be used through these macros: */
#define pool_get_name(pool) (pool)->v->get_name(pool)
#define pool_ref(pool) (pool)->v->ref(pool)
#define pool_unref(pool) ((*pool))->v->unref(pool)

#define p_new(pool, type, count) \
	((type *) p_malloc(pool, sizeof(type) * (count)))

#define p_malloc(pool, size) (pool)->v->malloc(pool, size)
#define p_realloc(pool, mem, old_size, new_size) \
	(pool)->v->realloc(pool, mem, old_size, new_size)

/* Free the memory. Currently it also sets memory to NULL, but that shouldn't
   be relied on as it's only an extra safety check. It might as well be later
   changed to some invalid pointer causing a segfault, or removed completely
   in some "optimization".. */
#define p_free(pool, mem) \
	STMT_START { \
          (pool)->v->free(pool, mem); \
          (mem) = NULL; \
	} STMT_END

/* A macro that's guaranteed to set mem = NULL. */
#define p_free_and_null(pool, mem) p_free(pool, mem)

#define p_clear(pool) (pool)->v->clear(pool)

#define p_get_max_easy_alloc_size(pool) \
	(pool)->v->get_max_easy_alloc_size(pool)

/* These functions are only for pools created with pool_alloconly_create(): */

/* Returns how much memory has been allocated from this pool. */
size_t pool_alloconly_get_total_used_size(pool_t pool);
/* Returns how much system memory has been allocated for this pool. */
size_t pool_alloconly_get_total_alloc_size(pool_t pool);

#endif
