/*
 mempool-alloconly.c : Memory pool for fast allocation of memory without
                       need to free it in small blocks

    Copyright (c) 2002 Timo Sirainen

    Permission is hereby granted, free of charge, to any person obtaining
    a copy of this software and associated documentation files (the
    "Software"), to deal in the Software without restriction, including
    without limitation the rights to use, copy, modify, merge, publish,
    distribute, sublicense, and/or sell copies of the Software, and to
    permit persons to whom the Software is furnished to do so, subject to
    the following conditions:

    The above copyright notice and this permission notice shall be
    included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
    OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
    MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
    IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
    CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
    TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
    SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

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

struct pool_alloc {
	union {
		size_t size;
		unsigned char alignment[MEM_ALIGN_SIZE];
	} size;
	unsigned char data[MEM_ALIGN_SIZE]; /* variable size */
};
#define SIZEOF_POOLALLOC (sizeof(struct pool_alloc)-MEM_ALIGN_SIZE)

static void pool_alloconly_ref(pool_t pool);
static void pool_alloconly_unref(pool_t pool);
static void *pool_alloconly_malloc(pool_t pool, size_t size);
static void pool_alloconly_free(pool_t pool, void *mem);
static void *pool_alloconly_realloc(pool_t pool, void *mem, size_t size);
static void pool_alloconly_clear(pool_t pool);

static void block_alloc(struct alloconly_pool *pool, size_t size);

static struct pool static_alloconly_pool = {
	pool_alloconly_ref,
	pool_alloconly_unref,

	pool_alloconly_malloc,
	pool_alloconly_free,

	pool_alloconly_realloc,

	pool_alloconly_clear
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
	free(apool->block);
	free(apool);
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
	struct pool_alloc *alloc;

	if (size == 0 || size > SSIZE_T_MAX)
		i_panic("Trying to allocate %"PRIuSIZE_T" bytes", size);

	size = MEM_ALIGN(size);

	if (apool->block->left < size + SIZEOF_POOLALLOC) {
		/* we need a new block */
		block_alloc(apool, size);
	}

	alloc = (struct pool_alloc *) (POOL_BLOCK_DATA(apool->block) +
				       apool->block->size - apool->block->left);
	alloc->size.size = size;

	apool->block->left -= size + SIZEOF_POOLALLOC;
	apool->block->last_alloc_size = size;
	return alloc->data;
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

static void *pool_alloconly_realloc(pool_t pool, void *mem, size_t size)
{
	struct alloconly_pool *apool = (struct alloconly_pool *) pool;
	struct pool_alloc *alloc;
	unsigned char *new_mem;
	size_t old_size;

	if (size == 0 || size > SSIZE_T_MAX)
		i_panic("Trying to allocate %"PRIuSIZE_T" bytes", size);

	if (mem == NULL)
		return pool_alloconly_malloc(pool, size);

	/* get old size */
	alloc = (struct pool_alloc *) ((char *) mem - SIZEOF_POOLALLOC);
	old_size = alloc->size.size;

	if (size <= old_size)
		return mem;

	size = MEM_ALIGN(size);

	/* see if we can directly grow it */
	if (!pool_try_grow(apool, mem, size)) {
		/* slow way - allocate + copy */
		new_mem = pool_alloconly_malloc(pool, size);
		memcpy(new_mem, mem, old_size);
		mem = new_mem;
	}

	if (size > old_size) {
                /* clear new data */
		memset((char *) mem + old_size, 0, size - old_size);
	}

        return mem;
}

static void pool_alloconly_clear(pool_t pool)
{
	struct alloconly_pool *apool = (struct alloconly_pool *) pool;
	struct pool_block *block;

	/* destroy all blocks but the last, which is the largest */
	while (apool->block->prev != NULL) {
		block = apool->block;
		apool->block = block->prev;

		free(block);
	}

	/* clear the last block */
	memset(POOL_BLOCK_DATA(apool->block), 0,
	       apool->block->size - apool->block->left);
	apool->block->left = apool->block->size;
	apool->block->last_alloc_size = 0;
}
