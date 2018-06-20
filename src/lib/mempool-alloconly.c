/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

/* @UNSAFE: whole file */
#include "lib.h"
#include "safe-memset.h"
#include "mempool.h"

/*
 * As the name implies, alloconly pools support only allocating memory.
 * Memory freeing is not supported, except as a special case - the pool's
 * last allocation can be freed.  Additionally, p_realloc() also tries to
 * grow an existing allocation if and only if it is the last allocation,
 * otherwise it just allocates a new memory area and copies the data there.
 *
 * Alloconly pools are commonly used for an object that builds its state
 * from many memory allocations, but doesn't change (much of) its state.
 * It is simpler to free such an object by destroying the entire memory
 * pool.
 *
 * Implementation
 * ==============
 *
 * Each alloconly pool contains a pool structure (struct alloconly_pool) to
 * keep track of alloconly-specific pool information and one or more blocks
 * (struct pool_block) that keep track of ranges of memory used to back the
 * allocations.  The blocks are kept in a linked list implementing a stack.
 * The block size decreases the further down the stack one goes.
 *
 * +-----------+
 * | alloconly |
 * |    pool   |
 * +-----+-----+
 *       |
 *       | block  +------------+ next  +------------+ next
 *       \------->| pool block |------>| pool block |------>...
 *                +------------+       +------------+
 *                |   <data>   |       |   <data>   |
 *                      .                    .
 *                      .                    .
 *                      .              |   <data>   |
 *                      .              +------------+
 *                |   <data>   |
 *                +------------+
 *
 * Creation
 * --------
 *
 * When an alloconly pool is created, one block is allocated.  This block is
 * large enough to hold the necessary internal structures (struct
 * alloconly_pool and struct pool_block) and still have enough space to
 * satisfy allocations for at least the amount of space requested by the
 * consumer via the size argument to pool_alloconly_create().
 *
 * Allocation
 * ----------
 *
 * Each allocation (via p_malloc()) checks the top-most block to see whether
 * or not it has enough space to satisfy the allocation.  If there is not
 * enough space, it allocates a new block (via block_alloc()) to serve as
 * the new top-most block.  This newly-allocated block is guaranteed to have
 * enough space for the allocation.  Then, regardless of whether or not a
 * new block was allocated, the allocation code reserves enough space in the
 * top-most block for the allocation and returns a pointer to it to the
 * caller.
 *
 * The free space tracking within each block is very simple.  In addition to
 * keeping track of the size of the block, the block header contains a
 * "pointer" to the beginning of free space.  A new allocation simply moves
 * this pointer by the number of bytes allocated.
 *
 * Reallocation
 * ------------
 *
 * If the passed in allocation is the last allocation in a block and there
 * is enough space after it, the allocation is resized.  Otherwise, a new
 * buffer is allocated (see Allocation above) and the contents are copied
 * over.
 *
 * Freeing
 * -------
 *
 * Freeing of the last allocation moves the "pointer" to free space back by
 * the size of the last allocation.
 *
 * Freeing of any other allocation is a no-op.
 *
 * Clearing
 * --------
 *
 * Clearing the pool is supposed to return the pool to the same state it was
 * in when it was first created.  To that end, the alloconly pool frees all
 * the blocks allocated since the pool's creation.  The remaining block
 * (allocated during creation) is reset to consider all the space for
 * allocations as available.
 *
 * In other words, the per-block free space tracking variables are set to
 * indicate that the full block is available and that there have been no
 * allocations.
 *
 * Finally, if the pool was created via pool_alloconly_create_clean(), all
 * blocks are safe_memset()/memset() to zero before being free()d.
 *
 * Destruction
 * -----------
 *
 * Destroying a pool first clears it (see above).  The clearing leaves the
 * pool in a minimal state with only one block allocated.  This remaining
 * block may be safe_memset() to zero if the pool was created with
 * pool_alloconly_create_clean().
 *
 * Since the pool structure itself is allocated from the first block, this
 * final call to free() will release the memory allocated for struct
 * alloconly_pool and struct pool.
 */

#ifndef DEBUG
#  define POOL_ALLOCONLY_MAX_EXTRA MEM_ALIGN(1)
#else
#  define POOL_ALLOCONLY_MAX_EXTRA \
	(MEM_ALIGN(sizeof(size_t)) + MEM_ALIGN(1) + MEM_ALIGN(SENTRY_COUNT))
#endif

struct alloconly_pool {
	struct pool pool;
	int refcount;

	struct pool_block *block;
#ifdef DEBUG
	const char *name;
	size_t base_size;
	bool disable_warning;
#endif
	bool clean_frees;
};

struct pool_block {
	struct pool_block *prev;

	size_t size;
	size_t left;
	size_t last_alloc_size;

	/* unsigned char data[]; */
};
#define SIZEOF_POOLBLOCK (MEM_ALIGN(sizeof(struct pool_block)))

#define POOL_BLOCK_DATA(block) \
	((unsigned char *) (block) + SIZEOF_POOLBLOCK)

#define DEFAULT_BASE_SIZE MEM_ALIGN(sizeof(struct alloconly_pool))

#ifdef DEBUG
#  define CLEAR_CHR 0xde
#  define SENTRY_COUNT 8
#else
#  define SENTRY_COUNT 0
#  define CLEAR_CHR 0
#endif

static const char *pool_alloconly_get_name(pool_t pool);
static void pool_alloconly_ref(pool_t pool);
static void pool_alloconly_unref(pool_t *pool);
static void *pool_alloconly_malloc(pool_t pool, size_t size);
static void pool_alloconly_free(pool_t pool, void *mem);
static void *pool_alloconly_realloc(pool_t pool, void *mem,
				    size_t old_size, size_t new_size);
static void pool_alloconly_clear(pool_t pool);
static size_t pool_alloconly_get_max_easy_alloc_size(pool_t pool);

static void block_alloc(struct alloconly_pool *pool, size_t size);

static const struct pool_vfuncs static_alloconly_pool_vfuncs = {
	pool_alloconly_get_name,

	pool_alloconly_ref,
	pool_alloconly_unref,

	pool_alloconly_malloc,
	pool_alloconly_free,

	pool_alloconly_realloc,

	pool_alloconly_clear,
	pool_alloconly_get_max_easy_alloc_size
};

static const struct pool static_alloconly_pool = {
	.v = &static_alloconly_pool_vfuncs,

	.alloconly_pool = TRUE,
	.datastack_pool = FALSE
};

#ifdef DEBUG
static void check_sentries(struct pool_block *block)
{
	const unsigned char *data = POOL_BLOCK_DATA(block);
	size_t i, max_pos, alloc_size, used_size;

	used_size = block->size - block->left;
	for (i = 0; i < used_size; ) {
		alloc_size = *(size_t *)(data + i);
		if (alloc_size == 0 || used_size - i < alloc_size)
			i_panic("mempool-alloconly: saved alloc size broken");
		i += MEM_ALIGN(sizeof(alloc_size));
		max_pos = i + MEM_ALIGN(alloc_size + SENTRY_COUNT);
		i += alloc_size;

		for (; i < max_pos; i++) {
			if (data[i] != CLEAR_CHR)
				i_panic("mempool-alloconly: buffer overflow");
		}
	}

	if (i != used_size)
		i_panic("mempool-alloconly: used_size wrong");

	/* The unused data must be NULs */
	for (; i < block->size; i++) {
		if (data[i] != '\0')
			i_unreached();
	}
	if (block->prev != NULL)
		check_sentries(block->prev);
}
#endif

pool_t pool_alloconly_create(const char *name ATTR_UNUSED, size_t size)
{
	struct alloconly_pool apool, *new_apool;
	size_t min_alloc = SIZEOF_POOLBLOCK +
		MEM_ALIGN(sizeof(struct alloconly_pool) + SENTRY_COUNT);

#ifdef DEBUG
	min_alloc += MEM_ALIGN(strlen(name) + 1 + SENTRY_COUNT) +
		sizeof(size_t)*2;
#endif

	/* create a fake alloconly_pool so we can call block_alloc() */
	i_zero(&apool);
	apool.pool = static_alloconly_pool;
	apool.refcount = 1;

	if (size < min_alloc)
		size = nearest_power(size + min_alloc);
	block_alloc(&apool, size);

	/* now allocate the actual alloconly_pool from the created block */
	new_apool = p_new(&apool.pool, struct alloconly_pool, 1);
	*new_apool = apool;
#ifdef DEBUG
	if (str_begins(name, MEMPOOL_GROWING) ||
	    getenv("DEBUG_SILENT") != NULL) {
		name += strlen(MEMPOOL_GROWING);
		new_apool->disable_warning = TRUE;
	}
	new_apool->name = p_strdup(&new_apool->pool, name);

	/* set base_size so p_clear() doesn't trash alloconly_pool structure. */
	new_apool->base_size = new_apool->block->size - new_apool->block->left;
	new_apool->block->last_alloc_size = 0;
#endif
	/* the first pool allocations must be from the first block */
	i_assert(new_apool->block->prev == NULL);

	return &new_apool->pool;
}

pool_t pool_alloconly_create_clean(const char *name, size_t size)
{
	struct alloconly_pool *apool;
	pool_t pool;

	pool = pool_alloconly_create(name, size);
	apool = (struct alloconly_pool *)pool;
	apool->clean_frees = TRUE;
	return pool;
}

static void pool_alloconly_destroy(struct alloconly_pool *apool)
{
	void *block;

	/* destroy all but the last block */
	pool_alloconly_clear(&apool->pool);

	/* destroy the last block */
	block = apool->block;
#ifdef DEBUG
	safe_memset(block, CLEAR_CHR, SIZEOF_POOLBLOCK + apool->block->size);
#else
	if (apool->clean_frees) {
		safe_memset(block, CLEAR_CHR,
			    SIZEOF_POOLBLOCK + apool->block->size);
	}
#endif

	free(block);
}

static const char *pool_alloconly_get_name(pool_t pool ATTR_UNUSED)
{
#ifdef DEBUG
	struct alloconly_pool *apool = (struct alloconly_pool *)pool;

	return apool->name;
#else
	return "alloconly";
#endif
}

static void pool_alloconly_ref(pool_t pool)
{
	struct alloconly_pool *apool = (struct alloconly_pool *)pool;

	apool->refcount++;
}

static void pool_alloconly_unref(pool_t *pool)
{
	struct alloconly_pool *apool = (struct alloconly_pool *)*pool;

	/* erase the pointer before freeing anything, as the pointer may
	   exist inside the pool's memory area */
	*pool = NULL;

	if (--apool->refcount > 0)
		return;

	pool_alloconly_destroy(apool);
}

static void block_alloc(struct alloconly_pool *apool, size_t size)
{
	struct pool_block *block;

	i_assert(size > SIZEOF_POOLBLOCK);
	i_assert(size <= SSIZE_T_MAX);

	if (apool->block != NULL) {
		/* each block is at least twice the size of the previous one */
		if (size <= apool->block->size)
			size += apool->block->size;

		/* avoid crashing in nearest_power() if size is too large */
		size = I_MIN(size, SSIZE_T_MAX);
		size = nearest_power(size);
		/* nearest_power() could have grown size to SSIZE_T_MAX+1 */
		size = I_MIN(size, SSIZE_T_MAX);
#ifdef DEBUG
		if (!apool->disable_warning) {
			/* i_debug() overwrites unallocated data in data
			   stack, so make sure everything is allocated before
			   calling it. */
			t_buffer_alloc_last_full();
			i_debug("Growing pool '%s' with: %"PRIuSIZE_T,
				  apool->name, size);
		}
#endif
	}

	block = calloc(size, 1);
	if (unlikely(block == NULL)) {
		i_fatal_status(FATAL_OUTOFMEM, "block_alloc(%"PRIuSIZE_T
			       "): Out of memory", size);
	}
	block->prev = apool->block;
	apool->block = block;

	block->size = size - SIZEOF_POOLBLOCK;
	block->left = block->size;
}

static void *pool_alloconly_malloc(pool_t pool, size_t size)
{
	struct alloconly_pool *apool = (struct alloconly_pool *)pool;
	void *mem;
	size_t alloc_size;

	if (unlikely(size == 0 || size > SSIZE_T_MAX - POOL_ALLOCONLY_MAX_EXTRA))
		i_panic("Trying to allocate %"PRIuSIZE_T" bytes", size);

#ifndef DEBUG
	alloc_size = MEM_ALIGN(size);
#else
	alloc_size = MEM_ALIGN(sizeof(size)) + MEM_ALIGN(size + SENTRY_COUNT);
#endif

	if (apool->block->left < alloc_size) {
		/* we need a new block */
		block_alloc(apool, alloc_size + SIZEOF_POOLBLOCK);
	}

	mem = POOL_BLOCK_DATA(apool->block) +
		(apool->block->size - apool->block->left);

	apool->block->left -= alloc_size;
	apool->block->last_alloc_size = alloc_size;
#ifdef DEBUG
	memcpy(mem, &size, sizeof(size));
	mem = PTR_OFFSET(mem, MEM_ALIGN(sizeof(size)));
	/* write CLEAR_CHRs to sentry */
	memset(PTR_OFFSET(mem, size), CLEAR_CHR,
	       MEM_ALIGN(size + SENTRY_COUNT) - size);
#endif
	return mem;
}

static void pool_alloconly_free(pool_t pool, void *mem)
{
	struct alloconly_pool *apool = (struct alloconly_pool *)pool;

	/* we can free only the last allocation */
	if (POOL_BLOCK_DATA(apool->block) +
	    (apool->block->size - apool->block->left -
	     apool->block->last_alloc_size) == mem) {
		memset(mem, 0, apool->block->last_alloc_size);
		apool->block->left += apool->block->last_alloc_size;
		apool->block->last_alloc_size = 0;
	}
}

static bool pool_alloconly_try_grow(struct alloconly_pool *apool, void *mem, size_t size)
{
	/* see if we want to grow the memory we allocated last */
	if (POOL_BLOCK_DATA(apool->block) +
	    (apool->block->size - apool->block->left -
	     apool->block->last_alloc_size) == mem) {
		/* yeah, see if we can grow */
		if (apool->block->left >= size-apool->block->last_alloc_size) {
			/* just shrink the available size */
			apool->block->left -=
				size - apool->block->last_alloc_size;
			apool->block->last_alloc_size = size;
			return TRUE;
		}
	}

	return FALSE;
}

static void *pool_alloconly_realloc(pool_t pool, void *mem,
				    size_t old_size, size_t new_size)
{
	struct alloconly_pool *apool = (struct alloconly_pool *)pool;
	unsigned char *new_mem;

	if (unlikely(new_size == 0 || new_size > SSIZE_T_MAX - POOL_ALLOCONLY_MAX_EXTRA))
		i_panic("Trying to allocate %"PRIuSIZE_T" bytes", new_size);

	if (mem == NULL)
		return pool_alloconly_malloc(pool, new_size);

	if (new_size <= old_size)
		return mem;

	new_size = MEM_ALIGN(new_size);

	/* see if we can directly grow it */
	if (!pool_alloconly_try_grow(apool, mem, new_size)) {
		/* slow way - allocate + copy */
		new_mem = pool_alloconly_malloc(pool, new_size);
		memcpy(new_mem, mem, old_size);
		mem = new_mem;
	}

	return mem;
}

static void pool_alloconly_clear(pool_t pool)
{
	struct alloconly_pool *apool = (struct alloconly_pool *)pool;
	struct pool_block *block;
	size_t base_size, avail_size;

#ifdef DEBUG
	check_sentries(apool->block);
#endif

	/* destroy all blocks but the oldest, which contains the
	   struct alloconly_pool allocation. */
	while (apool->block->prev != NULL) {
		block = apool->block;
		apool->block = block->prev;

#ifdef DEBUG
		safe_memset(block, CLEAR_CHR, SIZEOF_POOLBLOCK + block->size);
#else
		if (apool->clean_frees) {
			safe_memset(block, CLEAR_CHR,
				    SIZEOF_POOLBLOCK + block->size);
		}
#endif
		free(block);
	}

	/* clear the first block */
#ifdef DEBUG
	base_size = apool->base_size;
#else
	base_size = DEFAULT_BASE_SIZE;
#endif
	avail_size = apool->block->size - base_size;
	memset(PTR_OFFSET(POOL_BLOCK_DATA(apool->block), base_size), 0,
	       avail_size - apool->block->left);
	apool->block->left = avail_size;
	apool->block->last_alloc_size = 0;
}

static size_t pool_alloconly_get_max_easy_alloc_size(pool_t pool)
{
	struct alloconly_pool *apool = (struct alloconly_pool *)pool;

	return apool->block->left;
}

size_t pool_alloconly_get_total_used_size(pool_t pool)
{
	struct alloconly_pool *apool = (struct alloconly_pool *)pool;
	struct pool_block *block;
	size_t size = 0;

	i_assert(pool->v == &static_alloconly_pool_vfuncs);

	for (block = apool->block; block != NULL; block = block->prev)
		size += block->size - block->left;
	return size;
}

size_t pool_alloconly_get_total_alloc_size(pool_t pool)
{
	struct alloconly_pool *apool = (struct alloconly_pool *)pool;
	struct pool_block *block;
	size_t size = 0;

	i_assert(pool->v == &static_alloconly_pool_vfuncs);

	for (block = apool->block; block != NULL; block = block->prev)
		size += block->size + SIZEOF_POOLBLOCK;
	return size;
}
