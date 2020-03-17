#ifndef MEMPOOL_H
#define MEMPOOL_H

#include "macros.h"

/* When DEBUG is enabled, Dovecot warns whenever a memory pool is grown.
   This is done so that the initial pool size could be set large enough so that
   it wouldn't grow in normal use. For some memory pools it's too difficult
   to calculate a good initial size, so this prefix should be used with those
   pools to disable the warning. */
#define MEMPOOL_GROWING "GROWING-"

/* The maximum allocation size that's allowed.  Anything larger than that
   will panic.  No pool ever should need more than 4kB of overhead per
   allocation. */
#define POOL_MAX_ALLOC_SIZE	(SSIZE_T_MAX - 4096)

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
/* Like alloconly pool, but clear the memory before freeing it. The idea is
   that you could allocate memory for storing sensitive information from this
   pool, and be sure that it gets cleared from the memory when it's no longer
   needed. */
pool_t pool_alloconly_create_clean(const char *name, size_t size);

/* When allocating memory from returned pool, the data stack frame must be
   the same as it was when calling this function. pool_unref() also checks
   that the stack frame is the same. This should make it quite safe to use. */
pool_t pool_datastack_create(void);

/* Create new alloc pool. This is very similar to system pool, but it
   will deallocate all memory on deinit. */
pool_t pool_allocfree_create(const char *name);

/* Like alloc pool, but all memory is cleaned before freeing.
   See pool_alloconly_create_clean. */
pool_t pool_allocfree_create_clean(const char *name);

/* Similar to nearest_power(), but try not to exceed buffer's easy
   allocation size. If you don't have any explicit minimum size, use
   old_size + 1. */
size_t pool_get_exp_grown_size(pool_t pool, size_t old_size, size_t min_size);

/* We require sizeof(type) to be <= UINT_MAX. This allows compiler to optimize
   away the entire MALLOC_MULTIPLY() call on 64bit systems. */
#define p_new(pool, type, count) \
	((type *) p_malloc(pool, MALLOC_MULTIPLY((unsigned int)sizeof(type), (count))) + \
	 COMPILE_ERROR_IF_TRUE(sizeof(type) > UINT_MAX))

#define p_realloc_type(pool, mem, type, old_count, new_count) \
	((type *) p_realloc(pool, mem, \
	 MALLOC_MULTIPLY((unsigned int)sizeof(type), (old_count)), \
	 MALLOC_MULTIPLY((unsigned int)sizeof(type), (new_count))) + \
		COMPILE_ERROR_IF_TRUE(sizeof(type) > UINT_MAX))

static inline void * ATTR_MALLOC ATTR_RETURNS_NONNULL
p_malloc(pool_t pool, size_t size)
{
	if (unlikely(size == 0 || size > POOL_MAX_ALLOC_SIZE))
		i_panic("Trying to allocate %zu bytes", size);

	return pool->v->malloc(pool, size);
}

static inline void * ATTR_WARN_UNUSED_RESULT ATTR_RETURNS_NONNULL
p_realloc(pool_t pool, void *mem, size_t old_size, size_t new_size)
{
	if (unlikely(new_size == 0 || new_size > POOL_MAX_ALLOC_SIZE))
		i_panic("Trying to reallocate %zu -> %zu bytes",
			old_size, new_size);

	if (mem == NULL)
		return pool->v->malloc(pool, new_size);

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
	if (mem != NULL)
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
	if (*pool != NULL)
		(*pool)->v->unref(pool);
}

/* These functions are only for pools created with pool_alloconly_create(): */

/* Returns how much memory has been allocated from this pool. */
size_t pool_alloconly_get_total_used_size(pool_t pool);
/* Returns how much system memory has been allocated for this pool. */
size_t pool_alloconly_get_total_alloc_size(pool_t pool);

/* Returns how much memory has been allocated from this pool. */
size_t pool_allocfree_get_total_used_size(pool_t pool);
/* Returns how much system memory has been allocated for this pool. */
size_t pool_allocfree_get_total_alloc_size(pool_t pool);

/* private: */
void pool_system_free(pool_t pool, void *mem);

#endif
