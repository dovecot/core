/*
 mempool-system.c : Memory pool wrapper for malloc() + realloc() + free()

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

typedef struct {
	union {
		size_t size;
		unsigned char alignment[MEM_ALIGN_SIZE];
	} size;
	/* void data[]; */
} PoolAlloc;

static void pool_system_ref(Pool pool);
static void pool_system_unref(Pool pool);
static void *pool_system_malloc(Pool pool, size_t size);
static void pool_system_free(Pool pool, void *mem);
static void *pool_system_realloc(Pool pool, void *mem, size_t size);
static void pool_system_clear(Pool pool);

static struct Pool static_system_pool = {
	pool_system_ref,
	pool_system_unref,

	pool_system_malloc,
	pool_system_free,

	pool_system_realloc,

	pool_system_clear
};

Pool system_pool = &static_system_pool;

static void pool_system_ref(Pool pool __attr_unused__)
{
}

static void pool_system_unref(Pool pool __attr_unused__)
{
}

static void *pool_system_malloc(Pool pool __attr_unused__, size_t size)
{
	PoolAlloc *alloc;

	if (size == 0 || size > SSIZE_T_MAX)
		i_panic("Trying to allocate %"PRIuSIZE_T" bytes", size);

	alloc = calloc(sizeof(PoolAlloc) + size, 1);
	if (alloc == NULL)
		i_panic("pool_system_malloc(): Out of memory");
	alloc->size.size = size;

	return (char *) alloc + sizeof(PoolAlloc);
}

static void pool_system_free(Pool pool __attr_unused__, void *mem)
{
	if (mem != NULL)
		free((char *) mem - sizeof(PoolAlloc));
}

static void *pool_system_realloc(Pool pool __attr_unused__, void *mem,
				 size_t size)
{
	PoolAlloc *alloc;
	size_t old_size;
	char *rmem;

	if (size == 0 || size > SSIZE_T_MAX)
		i_panic("Trying to allocate %"PRIuSIZE_T" bytes", size);

	if (mem == NULL) {
		alloc = NULL;
		old_size = 0;
	} else {
		/* get old size */
		alloc = (PoolAlloc *) ((char *) mem - sizeof(PoolAlloc));
		old_size = alloc->size.size;
	}

        /* alloc & set new size */
	alloc = realloc(alloc, sizeof(PoolAlloc) + size);
	if (alloc == NULL)
		i_panic("pool_system_realloc(): Out of memory");
	alloc->size.size = size;

        rmem = (char *) alloc + sizeof(PoolAlloc);
	if (size > old_size) {
                /* clear new data */
		memset(rmem + old_size, 0, size-old_size);
	}

        return rmem;
}

static void pool_system_clear(Pool pool __attr_unused__)
{
	i_panic("pool_system_clear() must not be called");
}
