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

static const char *pool_system_get_name(pool_t pool);
static void pool_system_ref(pool_t pool);
static void pool_system_unref(pool_t pool);
static void *pool_system_malloc(pool_t pool, size_t size);
static void pool_system_free(pool_t pool, void *mem);
static void *pool_system_realloc(pool_t pool, void *mem,
				 size_t old_size, size_t new_size);
static void pool_system_clear(pool_t pool);

static struct pool static_system_pool = {
	pool_system_get_name,

	pool_system_ref,
	pool_system_unref,

	pool_system_malloc,
	pool_system_free,

	pool_system_realloc,

	pool_system_clear,

        FALSE
};

pool_t system_pool = &static_system_pool;

static const char *pool_system_get_name(pool_t pool __attr_unused__)
{
	return "system";
}

static void pool_system_ref(pool_t pool __attr_unused__)
{
}

static void pool_system_unref(pool_t pool __attr_unused__)
{
}

static void *pool_system_malloc(pool_t pool __attr_unused__, size_t size)
{
	void *mem;

	if (size == 0 || size > SSIZE_T_MAX)
		i_panic("Trying to allocate %"PRIuSIZE_T" bytes", size);

	mem = calloc(size, 1);
	if (mem == NULL)
		i_panic("pool_system_malloc(): Out of memory");

	return mem;
}

static void pool_system_free(pool_t pool __attr_unused__, void *mem)
{
	if (mem != NULL)
		free(mem);
}

static void *pool_system_realloc(pool_t pool __attr_unused__, void *mem,
				 size_t old_size, size_t new_size)
{
	if (new_size == 0 || new_size > SSIZE_T_MAX)
		i_panic("Trying to allocate %"PRIuSIZE_T" bytes", new_size);

	mem = realloc(mem, new_size);
	if (mem == NULL)
		i_panic("pool_system_realloc(): Out of memory");

	if (old_size < new_size) {
                /* clear new data */
		memset((char *) mem + old_size, 0, new_size - old_size);
	}

        return mem;
}

static void pool_system_clear(pool_t pool __attr_unused__)
{
	i_panic("pool_system_clear() must not be called");
}
