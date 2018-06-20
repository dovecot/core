/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "mempool.h"

/*
 * The datastack pool is a thin wrapper around the datastack API.  It exists
 * to allow datastack allocations via the pool API.
 *
 * Note: Do not confuse it with the *unsafe* datastack pool.
 *
 * Implementation
 * ==============
 *
 * A datastack pool maintains information about the datastack frame that was
 * in use when the pool was created so it can sanity check all p_new(),
 * p_malloc(), and p_realloc() calls.
 *
 * Creation
 * --------
 *
 * When a datastack pool is created, a new pool structure is allocated from
 * the datastack (via t_new()).  The current datastack frame number is saved
 * into the pool's private data (struct datastack_pool).
 *
 * Allocation & Reallocation
 * -------------------------
 *
 * After verifying that the saved datastack frame id matches the currently
 * active one, the p_malloc() and p_realloc() calls get directed to
 * t_malloc0() and t_try_realloc(), respectively.  There is no
 * per-allocation information to track.
 *
 * Freeing
 * -------
 *
 * Freeing is a no-op unless the currently active data stack frame id is
 * different from the one saved during pool creation, in which case the
 * process panics.
 *
 * Clearing
 * --------
 *
 * A no-op.
 *
 * Destruction
 * -----------
 *
 * Since the memory backing the pool structure itself is allocated from the
 * datastack via t_new(), the pool and all allocations it made are freed
 * when the datastack frame is popped.
 *
 * Even though the pool maintains a reference count, no memory is freed when
 * it reaches zero.  Once the reference count reaches zero, the state of the
 * pool is undefined and none of its memory maybe be used.
 */

static const char *pool_data_stack_get_name(pool_t pool);
static void pool_data_stack_ref(pool_t pool);
static void pool_data_stack_unref(pool_t *pool);
static void *pool_data_stack_malloc(pool_t pool, size_t size);
static void pool_data_stack_free(pool_t pool, void *mem);
static void *pool_data_stack_realloc(pool_t pool, void *mem,
				     size_t old_size, size_t new_size);
static void pool_data_stack_clear(pool_t pool);
static size_t pool_data_stack_get_max_easy_alloc_size(pool_t pool);

static struct pool_vfuncs static_data_stack_pool_vfuncs = {
	pool_data_stack_get_name,

	pool_data_stack_ref,
	pool_data_stack_unref,

	pool_data_stack_malloc,
	pool_data_stack_free,

	pool_data_stack_realloc,

	pool_data_stack_clear,
	pool_data_stack_get_max_easy_alloc_size
};

static const struct pool static_data_stack_pool = {
	.v = &static_data_stack_pool_vfuncs,

	.alloconly_pool = TRUE,
	.datastack_pool = TRUE
};

struct datastack_pool {
	struct pool pool;
	int refcount;

	unsigned int data_stack_frame;
};

pool_t pool_datastack_create(void)
{
	struct datastack_pool *dpool;

	dpool = t_new(struct datastack_pool, 1);
	dpool->pool = static_data_stack_pool;
	dpool->refcount = 1;
	dpool->data_stack_frame = data_stack_frame_id;
	return &dpool->pool;
}

static const char *pool_data_stack_get_name(pool_t pool ATTR_UNUSED)
{
	return "data stack";
}

static void pool_data_stack_ref(pool_t pool)
{
	struct datastack_pool *dpool =
		container_of(pool, struct datastack_pool, pool);

	if (unlikely(dpool->data_stack_frame != data_stack_frame_id))
		i_panic("pool_data_stack_ref(): stack frame changed");

	dpool->refcount++;
}

static void pool_data_stack_unref(pool_t *pool)
{
	struct datastack_pool *dpool =
		container_of(*pool, struct datastack_pool, pool);

	if (unlikely(dpool->data_stack_frame != data_stack_frame_id))
		i_panic("pool_data_stack_unref(): stack frame changed");

	dpool->refcount--;
	i_assert(dpool->refcount >= 0);

	*pool = NULL;
}

static void *pool_data_stack_malloc(pool_t pool ATTR_UNUSED, size_t size)
{
	struct datastack_pool *dpool =
		container_of(pool, struct datastack_pool, pool);

	if (unlikely(dpool->data_stack_frame != data_stack_frame_id))
		i_panic("pool_data_stack_malloc(): stack frame changed");

	return t_malloc0(size);
}

static void pool_data_stack_free(pool_t pool, void *mem ATTR_UNUSED)
{
	struct datastack_pool *dpool =
		container_of(pool, struct datastack_pool, pool);

	if (unlikely(dpool->data_stack_frame != data_stack_frame_id))
		i_panic("pool_data_stack_free(): stack frame changed");
}

static void *pool_data_stack_realloc(pool_t pool, void *mem,
				     size_t old_size, size_t new_size)
{
	struct datastack_pool *dpool =
		container_of(pool, struct datastack_pool, pool);
	void *new_mem;

	/* @UNSAFE */
	if (unlikely(dpool->data_stack_frame != data_stack_frame_id))
		i_panic("pool_data_stack_realloc(): stack frame changed");

	if (mem == NULL)
		return pool_data_stack_malloc(pool, new_size);

	if (old_size >= new_size)
		return mem;

	if (!t_try_realloc(mem, new_size)) {
		new_mem = t_malloc_no0(new_size);
		memcpy(new_mem, mem, old_size);
		mem = new_mem;
	}

	memset((char *) mem + old_size, 0, new_size - old_size);
	return mem;
}

static void pool_data_stack_clear(pool_t pool ATTR_UNUSED)
{
}

static size_t
pool_data_stack_get_max_easy_alloc_size(pool_t pool ATTR_UNUSED)
{
	return t_get_bytes_available();
}
