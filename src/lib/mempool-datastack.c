/*
 mempool-data-stack.c : Memory pool wrapper for data stack

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

struct pool_alloc {
	union {
		size_t size;
		unsigned char alignment[MEM_ALIGN_SIZE];
	} size;
	/* void data[]; */
};

static void pool_data_stack_ref(pool_t pool);
static void pool_data_stack_unref(pool_t pool);
static void *pool_data_stack_malloc(pool_t pool, size_t size);
static void pool_data_stack_free(pool_t pool, void *mem);
static void *pool_data_stack_realloc(pool_t pool, void *mem, size_t size);
static void pool_data_stack_clear(pool_t pool);

static struct pool static_data_stack_pool = {
	pool_data_stack_ref,
	pool_data_stack_unref,

	pool_data_stack_malloc,
	pool_data_stack_free,

	pool_data_stack_realloc,

	pool_data_stack_clear
};

pool_t data_stack_pool = &static_data_stack_pool;

static void pool_data_stack_ref(pool_t pool __attr_unused__)
{
}

static void pool_data_stack_unref(pool_t pool __attr_unused__)
{
}

static void *pool_data_stack_malloc(pool_t pool __attr_unused__, size_t size)
{
	struct pool_alloc *alloc;

	if (size == 0 || size > SSIZE_T_MAX)
		i_panic("Trying to allocate %"PRIuSIZE_T" bytes", size);

	alloc = t_malloc0(sizeof(struct pool_alloc) + size);
	alloc->size.size = size;

	return (char *) alloc + sizeof(struct pool_alloc);
}

static void pool_data_stack_free(pool_t pool __attr_unused__,
				 void *mem __attr_unused__)
{
}

static void *pool_data_stack_realloc(pool_t pool __attr_unused__,
				     void *mem, size_t size)
{
	/* @UNSAFE */
	struct pool_alloc *alloc, *new_alloc;
        size_t old_size;
	unsigned char *rmem;

	if (size == 0 || size > SSIZE_T_MAX)
		i_panic("Trying to allocate %"PRIuSIZE_T" bytes", size);

	if (mem == NULL)
		return pool_data_stack_malloc(pool, size);

	/* get old size */
	alloc = (struct pool_alloc *)
		((char *) mem - sizeof(struct pool_alloc));
	old_size = alloc->size.size;

	if (old_size >= size)
		return mem;

	if (!t_try_realloc(alloc, sizeof(struct pool_alloc) + size)) {
		new_alloc = t_malloc(sizeof(struct pool_alloc) + size);
		memcpy(new_alloc, alloc, old_size + sizeof(struct pool_alloc));
		alloc = new_alloc;
	}
	alloc->size.size = size;

        rmem = (unsigned char *) alloc + sizeof(struct pool_alloc);
	memset(rmem + old_size, 0, size-old_size);
	return rmem;
}

static void pool_data_stack_clear(pool_t pool __attr_unused__)
{
}
