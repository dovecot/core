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

#include "lib.h"
#include "mempool.h"

#include <stdlib.h>

#define MAX_ALLOC_SIZE (UINT_MAX - sizeof(unsigned int))

typedef struct _PoolBlock PoolBlock;

typedef struct {
	struct Pool pool;
	int refcount;

	PoolBlock *block;
	unsigned int last_alloc_size;

	char name[MEM_ALIGN_SIZE]; /* variable size */
} AlloconlyPool;
#define SIZEOF_ALLOCONLYPOOL (sizeof(AlloconlyPool)-MEM_ALIGN_SIZE)

struct _PoolBlock {
	PoolBlock *prev;

	unsigned int size;
	unsigned int left;

	/* unsigned char data[]; */
};
#define SIZEOF_POOLBLOCK (MEM_ALIGN(sizeof(PoolBlock)))

#define POOL_BLOCK_DATA(block) \
	((char *) (block) + SIZEOF_POOLBLOCK)

typedef struct {
	union {
		unsigned int size;
		unsigned char alignment[MEM_ALIGN_SIZE];
	} size;
	unsigned char data[MEM_ALIGN_SIZE]; /* variable size */
} PoolAlloc;
#define SIZEOF_POOLALLOC (sizeof(PoolAlloc)-MEM_ALIGN_SIZE)

static struct Pool static_alloconly_pool;
static void pool_alloconly_clear(Pool pool);

static void block_alloc(AlloconlyPool *pool, unsigned int size);
static void *pool_alloconly_realloc_min(Pool pool, void *mem,
					unsigned int size);

Pool pool_alloconly_create(const char *name, unsigned int size)
{
	AlloconlyPool *apool;
	int len;

	len = strlen(name);

	apool = calloc(SIZEOF_ALLOCONLYPOOL + len+1, 1);
	apool->pool = static_alloconly_pool;
	apool->refcount = 1;

	block_alloc(apool, size);

	strcpy(apool->name, name);
	return (Pool) apool;
}

static void pool_alloconly_destroy(AlloconlyPool *apool)
{
	/* destroy all but the last block */
	pool_alloconly_clear(&apool->pool);

	/* destroy the last block */
	free(apool->block);
	free(apool);
}

static void pool_alloconly_ref(Pool pool)
{
	AlloconlyPool *apool = (AlloconlyPool *) pool;

	apool->refcount++;
}

static void pool_alloconly_unref(Pool pool)
{
	AlloconlyPool *apool = (AlloconlyPool *) pool;

	if (--apool->refcount == 0)
		pool_alloconly_destroy(apool);
}

static void block_alloc(AlloconlyPool *apool, unsigned int size)
{
	PoolBlock *block;

	/* each block is at least twice the size of the previous one */
	if (apool->block != NULL)
		size += apool->block->size;

	if (size <= SIZEOF_POOLBLOCK)
		size += SIZEOF_POOLBLOCK;
	size = nearest_power(size);

	block = calloc(size, 1);
	block->prev = apool->block;
	apool->block = block;

	block->size = size - SIZEOF_POOLBLOCK;
	block->left = block->size;
}

static void *pool_alloconly_malloc(Pool pool, unsigned int size)
{
	AlloconlyPool *apool = (AlloconlyPool *) pool;
	PoolAlloc *alloc;

	size = MEM_ALIGN(size);

	if (apool->block->left < size + SIZEOF_POOLALLOC) {
		/* we need a new block */
		block_alloc(apool, size);
	}

	alloc = (PoolAlloc *) (POOL_BLOCK_DATA(apool->block) +
			       apool->block->size - apool->block->left);
	alloc->size.size = size;

	apool->block->left -= size + SIZEOF_POOLALLOC;
	apool->last_alloc_size = size;
	return alloc->data;
}

static void pool_alloconly_free(Pool pool __attr_unused__,
				void *mem __attr_unused__)
{
	/* ignore */
}

static void *pool_alloconly_realloc(Pool pool, void *mem, unsigned int size)
{
	/* there's no point in shrinking the memory usage,
	   so just do the same as realloc_min() */
	return pool_alloconly_realloc_min(pool, mem, size);
}

static int pool_try_grow(AlloconlyPool *apool, void *mem, unsigned int size)
{
	/* see if we want to grow the memory we allocated last */
	if (POOL_BLOCK_DATA(apool->block) + (apool->block->size -
					     apool->block->left -
					     apool->last_alloc_size) == mem) {
		/* yeah, see if we can grow */
		if (apool->block->left >= size-apool->last_alloc_size) {
			/* just shrink the available size */
			apool->block->left -= size - apool->last_alloc_size;
			apool->last_alloc_size = size;
			return TRUE;
		}
	}

	return FALSE;
}

static void *pool_alloconly_realloc_min(Pool pool, void *mem, unsigned int size)
{
	AlloconlyPool *apool = (AlloconlyPool *) pool;
	PoolAlloc *alloc;
	unsigned char *new_mem;
	unsigned int old_size;

	if (mem == NULL) {
		alloc = NULL;
		old_size = 0;
	} else {
		/* get old size */
                alloc = (PoolAlloc *) ((char *) mem - SIZEOF_POOLALLOC);
		old_size = alloc->size.size;
	}

	if (old_size >= size)
		return mem;

	size = MEM_ALIGN(size);

	/* see if we can directly grow it */
	if (pool_try_grow(apool, mem, size))
		return mem;

	/* slow way - allocate + copy */
        new_mem = pool_alloconly_malloc(pool, size);
	if (size > old_size) {
                /* clear new data */
		memset(new_mem + old_size, 0, size - old_size);
	}

        return new_mem;
}

static void pool_alloconly_clear(Pool pool)
{
	AlloconlyPool *apool = (AlloconlyPool *) pool;
	PoolBlock *block;

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

	apool->last_alloc_size = 0;
}

static struct Pool static_alloconly_pool = {
	pool_alloconly_ref,
	pool_alloconly_unref,

	pool_alloconly_malloc,
	pool_alloconly_free,

	pool_alloconly_realloc,
	pool_alloconly_realloc_min,

	pool_alloconly_clear
};
