/* Copyright (c) 2002-2003 Timo Sirainen */

/* @UNSAFE: whole file */

#include "lib.h"
#include "mempool.h"

#include <stdlib.h>

#define MAX_ALLOC_SIZE SSIZE_T_MAX

struct alloconly_pool {
	struct pool pool;
	int refcount;

	struct pool_block *block;

	char name[MEM_ALIGN_SIZE]; /* variable size */
};
#define SIZEOF_ALLOCONLYPOOL (sizeof(struct alloconly_pool)-MEM_ALIGN_SIZE)

struct pool_block {
	struct pool_block *prev;

	size_t size;
	size_t left;
	size_t last_alloc_size;

	/* unsigned char data[]; */
};
#define SIZEOF_POOLBLOCK (MEM_ALIGN(sizeof(struct pool_block)))

#define POOL_BLOCK_DATA(block) \
	((char *) (block) + SIZEOF_POOLBLOCK)

static const char *pool_alloconly_get_name(pool_t pool);
static void pool_alloconly_ref(pool_t pool);
static void pool_alloconly_unref(pool_t pool);
static void *pool_alloconly_malloc(pool_t pool, size_t size);
static void pool_alloconly_free(pool_t pool, void *mem);
static void *pool_alloconly_realloc(pool_t pool, void *mem,
				    size_t old_size, size_t new_size);
static void pool_alloconly_clear(pool_t pool);

static void block_alloc(struct alloconly_pool *pool, size_t size);

static struct pool static_alloconly_pool = {
	pool_alloconly_get_name,

	pool_alloconly_ref,
	pool_alloconly_unref,

	pool_alloconly_malloc,
	pool_alloconly_free,

	pool_alloconly_realloc,

	pool_alloconly_clear,

	TRUE,
	FALSE
};

pool_t pool_alloconly_create(const char *name, size_t size)
{
	struct alloconly_pool *apool;
	int len;

	len = strlen(name);

	apool = calloc(SIZEOF_ALLOCONLYPOOL + len+1, 1);
	if (apool == NULL)
		i_panic("pool_alloconly_create(): Out of memory");
	apool->pool = static_alloconly_pool;
	apool->refcount = 1;
	memcpy(apool->name, name, len+1);

	block_alloc(apool, size);
	return (struct pool *) apool;
}

static void pool_alloconly_destroy(struct alloconly_pool *apool)
{
	/* destroy all but the last block */
	pool_alloconly_clear(&apool->pool);

	/* destroy the last block */
#ifdef DEBUG
	memset(apool->block, 0xde, SIZEOF_POOLBLOCK + apool->block->size);
#endif
	free(apool->block);
	free(apool);
}

static const char *pool_alloconly_get_name(pool_t pool)
{
	struct alloconly_pool *apool = (struct alloconly_pool *) pool;

	return apool->name;
}

static void pool_alloconly_ref(pool_t pool)
{
	struct alloconly_pool *apool = (struct alloconly_pool *) pool;

	apool->refcount++;
}

static void pool_alloconly_unref(pool_t pool)
{
	struct alloconly_pool *apool = (struct alloconly_pool *) pool;

	if (--apool->refcount == 0)
		pool_alloconly_destroy(apool);
}

static void block_alloc(struct alloconly_pool *apool, size_t size)
{
	struct pool_block *block;

	/* each block is at least twice the size of the previous one */
	if (apool->block != NULL && size <= apool->block->size)
		size += apool->block->size;

	size = nearest_power(size + SIZEOF_POOLBLOCK);

#ifdef DEBUG
	if (apool->block != NULL) {
		i_warning("Growing pool '%s' with: %"PRIuSIZE_T,
			  apool->name, size);
	}
#endif

	block = calloc(size, 1);
	if (block == NULL)
		i_panic("block_alloc(): Out of memory");
	block->prev = apool->block;
	apool->block = block;

	block->size = size - SIZEOF_POOLBLOCK;
	block->left = block->size;
}

static void *pool_alloconly_malloc(pool_t pool, size_t size)
{
	struct alloconly_pool *apool = (struct alloconly_pool *) pool;
	void *mem;

	if (size == 0 || size > SSIZE_T_MAX)
		i_panic("Trying to allocate %"PRIuSIZE_T" bytes", size);

	size = MEM_ALIGN(size);

	if (apool->block->left < size) {
		/* we need a new block */
		block_alloc(apool, size);
	}

	mem = POOL_BLOCK_DATA(apool->block) +
		(apool->block->size - apool->block->left);

	apool->block->left -= size;
	apool->block->last_alloc_size = size;
	return mem;
}

static void pool_alloconly_free(pool_t pool __attr_unused__,
				void *mem __attr_unused__)
{
	/* ignore */
}

static int pool_try_grow(struct alloconly_pool *apool, void *mem, size_t size)
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
	struct alloconly_pool *apool = (struct alloconly_pool *) pool;
	unsigned char *new_mem;

	if (new_size == 0 || new_size > SSIZE_T_MAX)
		i_panic("Trying to allocate %"PRIuSIZE_T" bytes", new_size);

	if (mem == NULL)
		return pool_alloconly_malloc(pool, new_size);

	if (new_size <= old_size)
		return mem;

	new_size = MEM_ALIGN(new_size);

	/* see if we can directly grow it */
	if (!pool_try_grow(apool, mem, new_size)) {
		/* slow way - allocate + copy */
		new_mem = pool_alloconly_malloc(pool, new_size);
		memcpy(new_mem, mem, old_size);
		mem = new_mem;
	}

        return mem;
}

static void pool_alloconly_clear(pool_t pool)
{
	struct alloconly_pool *apool = (struct alloconly_pool *) pool;
	struct pool_block *block;

	/* destroy all blocks but the first, which is the largest */
	while (apool->block->prev != NULL) {
		block = apool->block->prev;
		apool->block->prev = block->prev;

#ifdef DEBUG
		memset(block, 0xde, SIZEOF_POOLBLOCK + block->size);
#endif
		free(block);
	}

	/* clear the block */
	memset(POOL_BLOCK_DATA(apool->block), 0,
	       apool->block->size - apool->block->left);
	apool->block->left = apool->block->size;
	apool->block->last_alloc_size = 0;
}
