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

	void *(*malloc)(pool_t pool, size_t size) ATTR_RETURNS_NONNULL;
	void (*free)(pool_t pool, void *mem);

	/* memory in old_size..new_size will be zeroed */
	void *(*realloc)(pool_t pool, void *mem,
			 size_t old_size, size_t new_size)
		ATTR_WARN_UNUSED_RESULT ATTR_RETURNS_NONNULL;

	/* Frees all the memory in pool. NOTE: system_pool doesn't support
	   this and crashes if it's used */
	void (*clear)(pool_t pool);

	/* Returns the maximum amount of bytes that can be allocated with
	   minimal trouble. If there's no such concept, always returns 0. */
	size_t (*get_max_easy_alloc_size)(pool_t pool);
};

struct pool {
	const struct pool_vfuncs *v;

	bool alloconly_pool:1;
	bool datastack_pool:1;
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

#define p_new(pool, type, count) \
	((type *) p_malloc(pool, sizeof(type) * (count)))
static inline void * ATTR_MALLOC ATTR_RETURNS_NONNULL
p_malloc(pool_t pool, size_t size)
{
	return pool->v->malloc(pool, size);
}

static inline void * ATTR_WARN_UNUSED_RESULT ATTR_RETURNS_NONNULL
p_realloc(pool_t pool, void *mem, size_t old_size, size_t new_size)
{
	return pool->v->realloc(pool, mem, old_size, new_size);
}

/* Free the memory. p_free() and p_free_and_null() are now guaranteed to both
   set mem=NULL, so either one of them can be used. */
#define p_free(pool, mem) \
	STMT_START { \
		p_free_internal(pool, mem);	\
		(mem) = NULL;			\
	} STMT_END
#define p_free_and_null(pool, mem) p_free(pool, mem)

static inline void p_free_internal(pool_t pool, void *mem)
{
	pool->v->free(pool, mem);
}

static inline void p_clear(pool_t pool)
{
	pool->v->clear(pool);
}

static inline size_t p_get_max_easy_alloc_size(pool_t pool)
{
	return pool->v->get_max_easy_alloc_size(pool);
}

static inline const char *pool_get_name(pool_t pool)
{
	return pool->v->get_name(pool);
}

static inline void pool_ref(pool_t pool)
{
	pool->v->ref(pool);
}

static inline void pool_unref(pool_t *pool)
{
	(*pool)->v->unref(pool);
}

/* These functions are only for pools created with pool_alloconly_create(): */

/* Returns how much memory has been allocated from this pool. */
size_t pool_alloconly_get_total_used_size(pool_t pool);
/* Returns how much system memory has been allocated for this pool. */
size_t pool_alloconly_get_total_alloc_size(pool_t pool);

/* private: */
void pool_system_free(pool_t pool, void *mem);

#endif
