/*
 temp-mempool.c : Memory pool for temporary memory allocations

    Copyright (c) 2001-2002 Timo Sirainen

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

#include <stdlib.h>

#include "lib.h"
#include "temp-mempool.h"

/* #define TEMP_POOL_DISABLE */

#ifndef TEMP_POOL_DISABLE

/* max. number of bytes to even try to allocate. This is done just to avoid
   allocating less memory than was actually requested because of integer
   overflows. */
#define MAX_ALLOC_SIZE (UINT_MAX - (MEM_ALIGN_SIZE-1))

/* Initial pool size - this should be kept in a size that doesn't exceed
   in a normal use to keep it fast. */
#define INITIAL_POOL_SIZE (1024*32)

typedef struct _MemBlock MemBlock;
typedef struct _MemBlockStack MemBlockStack;

struct _MemBlock {
	MemBlock *next;

	unsigned int size, left;
	unsigned char data[1];
};

/* current_stack contains last t_push()ed blocks. After that new
   MemBlockStack is created and it's ->prev is set to current_stack. */
#define MEM_LIST_BLOCK_COUNT 16

struct _MemBlockStack {
	MemBlockStack *prev;

	MemBlock *block[MEM_LIST_BLOCK_COUNT];
        int block_space_used[MEM_LIST_BLOCK_COUNT];
};

static int stack_pos; /* next free position in current_stack->block[] */
static MemBlockStack *current_stack; /* current stack position */
static MemBlockStack *unused_stack_list; /* unused stack blocks */

static MemBlock *current_block; /* block currently used for allocation */
static MemBlock *unused_block; /* largest unused block is kept here */

static int last_alloc_size;

static MemBlock *last_buffer_block;
static unsigned int last_buffer_size;

int t_push(void)
{
        MemBlockStack *stack;

	if (stack_pos == MEM_LIST_BLOCK_COUNT) {
		/* stack list full */
		stack_pos = 0;
		if (unused_stack_list == NULL) {
			/* allocate new stack */
			stack = calloc(sizeof(MemBlockStack), 1);
			if (stack == NULL)
				i_panic("t_push(): Out of memory");
		} else {
			/* use existing unused stack */
			stack = unused_stack_list;
			unused_stack_list = unused_stack_list->prev;
		}

		stack->prev = current_stack;
		current_stack = stack;
	}

	/* mark our current position */
	current_stack->block[stack_pos] = current_block;
	current_stack->block_space_used[stack_pos] = current_block->left;

        return stack_pos++;
}

static void free_blocks(MemBlock *block)
{
	/* free all the blocks, except if any of them is bigger than
	   unused_block, replace it */
	while (block != NULL) {
		if (unused_block == NULL || block->size > unused_block->size) {
			free(unused_block);
			unused_block = block;
		} else {
			free(block);
		}

		block = block->next;
	}
}

int t_pop(void)
{
	MemBlockStack *stack;

	if (stack_pos == 0)
		i_panic("t_pop() called with empty stack");
	stack_pos--;

	/* update the current block */
	current_block = current_stack->block[stack_pos];
	current_block->left = current_stack->block_space_used[stack_pos];

	if (current_block->next != NULL) {
		/* free unused blocks */
		free_blocks(current_block->next);
		current_block->next = NULL;
	}

	if (stack_pos == 0) {
		/* stack block is now unused, add it to unused list */
		stack_pos = MEM_LIST_BLOCK_COUNT;

		stack = current_stack;
		current_stack = stack->prev;

		stack->prev = unused_stack_list;
		unused_stack_list = stack;
	}

        return stack_pos;
}

static MemBlock *mem_block_alloc(unsigned int min_size)
{
	MemBlock *block;
	unsigned int prev_size, alloc_size;

	prev_size = current_block == NULL ? 0 : current_block->size;
	alloc_size = nearest_power(prev_size + min_size);

	block = malloc(sizeof(MemBlock)-1 + alloc_size);
	if (block == NULL) {
		i_panic("mem_block_alloc(): "
			"Out of memory when allocating %u bytes",
			sizeof(MemBlock)-1 + alloc_size);
	}
	block->size = alloc_size;
	block->next = NULL;

	return block;
}

static void *t_malloc_real(unsigned int size, int permanent)
{
	MemBlock *block;
        void *ret;

	if (size == 0)
		return NULL;

	if (size > MAX_ALLOC_SIZE)
		i_panic("Trying to allocate too much memory");

	/* reset t_buffer_get() mark - not really needed but makes it easier
	   to notice if t_malloc() is called between t_buffer_get() and
	   t_buffer_alloc() */
        last_buffer_block = NULL;

	/* allocate only aligned amount of memory so alignment comes
	   always properly */
	size = MEM_ALIGN(size);

	/* used for t_try_grow() */
	last_alloc_size = size;

	if (current_block->left >= size) {
		/* enough space in current block, use it */
		ret = current_block->data +
			(current_block->size - current_block->left);
                if (permanent)
			current_block->left -= size;
		return ret;
	}

	/* current block is full, see if we can use the unused_block */
	if (unused_block != NULL && unused_block->size >= size) {
		block = unused_block;
		unused_block = NULL;
	} else {
		block = mem_block_alloc(size);
	}

	block->left = block->size;
	if (permanent)
		block->left -= size;
	block->next = NULL;

	current_block->next = block;
	current_block = block;

        return current_block->data;
}

void *t_malloc(unsigned int size)
{
        return t_malloc_real(size, TRUE);
}

void *t_malloc0(unsigned int size)
{
	void *mem;

	mem = t_malloc_real(size, TRUE);
	memset(mem, 0, size);
        return mem;
}

int t_try_grow(void *mem, unsigned int size)
{
	/* see if we want to grow the memory we allocated last */
	if (current_block->data + (current_block->size -
				   current_block->left -
				   last_alloc_size) == mem) {
		/* yeah, see if we can grow */
		size = MEM_ALIGN(size);
		if (current_block->left >= size-last_alloc_size) {
			/* just shrink the available size */
			current_block->left -= size - last_alloc_size;
			last_alloc_size = size;
			return TRUE;
		}
	}

	return FALSE;
}

void *t_buffer_get(unsigned int size)
{
	void *ret;

	ret = t_malloc_real(size, FALSE);

	last_buffer_size = size;
	last_buffer_block = current_block;
	return ret;
}

void *t_buffer_reget(void *buffer, unsigned int size)
{
	unsigned int old_size;
        void *new_buffer;

	old_size = last_buffer_size;
	if (size <= old_size)
                return buffer;

	new_buffer = t_buffer_get(size);
	if (new_buffer != buffer)
                memcpy(new_buffer, buffer, old_size);

        return new_buffer;
}

void t_buffer_alloc(unsigned int size)
{
	i_assert(last_buffer_block != NULL);
	i_assert(last_buffer_size >= size);
	i_assert(current_block->left >= size);

	/* we've already reserved the space, now we just mark it used */
	t_malloc_real(size, TRUE);
}

void temp_mempool_init(void)
{
	current_block = mem_block_alloc(INITIAL_POOL_SIZE);
	current_block->left = current_block->size;
	current_block->next = NULL;

	current_stack = NULL;
	unused_stack_list = NULL;
	stack_pos = MEM_LIST_BLOCK_COUNT;

	t_push();

        last_alloc_size = 0;

        last_buffer_block = NULL;
	last_buffer_size = 0;
}

void temp_mempool_deinit(void)
{
	t_pop();

	if (stack_pos != MEM_LIST_BLOCK_COUNT)
		i_panic("Missing t_pop() call");

	while (unused_stack_list != NULL) {
                MemBlockStack *stack = unused_stack_list;
		unused_stack_list = unused_stack_list->prev;

                free(stack);
	}

	free(current_block);
	free(unused_block);
}

#else

typedef struct _Stack Stack;
typedef struct _Alloc Alloc;

struct _Stack {
	Stack *next;
	Alloc *allocs;
};

struct _Alloc {
	Alloc *next;
	void *mem;
};

static int stack_counter;
static Stack *current_stack;
static void *buffer_mem;

int t_push(void)
{
	Stack *stack;

	stack = malloc(sizeof(Stack));
	stack->allocs = NULL;

	stack->next = current_stack;
	current_stack = stack;
	return stack_counter++;
}

int t_pop(void)
{
	Stack *stack;
	Alloc *alloc;

	stack = current_stack;
	current_stack = stack->next;

	while (stack->allocs != NULL) {
		alloc = stack->allocs;
		stack->allocs = alloc->next;

		free(alloc->mem);
		free(alloc);
	}

	free(stack);
	return --stack_counter;
}

static void add_alloc(void *mem)
{
	Alloc *alloc;

	alloc = malloc(sizeof(Alloc));
	alloc->mem = mem;
	alloc->next = current_stack->allocs;
	current_stack->allocs = alloc;

	if (buffer_mem != NULL) {
		free(buffer_mem);
		buffer_mem = NULL;
	}
}

void *t_malloc(unsigned int size)
{
	void *mem;

	mem = malloc(size);
	add_alloc(mem);
	return mem;
}

void *t_malloc0(unsigned int size)
{
	void *mem;

	mem = calloc(size, 1);
	add_alloc(mem);
	return mem;
}

int t_try_grow(void *mem, unsigned int size)
{
	void *new_mem;

	new_mem = realloc(mem, size);
	if (new_mem == mem)
		return TRUE;

	free(new_mem);
	return FALSE;
}

void *t_buffer_get(unsigned int size)
{
	buffer_mem = realloc(buffer_mem, size);
	return buffer_mem;
}

void *t_buffer_reget(void *buffer, unsigned int size)
{
	i_assert(buffer == buffer_mem);

	buffer_mem = realloc(buffer_mem, size);
	return buffer_mem;
}

void t_buffer_alloc(unsigned int size)
{
	void *mem;

	i_assert(buffer_mem != NULL);

	mem = buffer_mem;
	buffer_mem = NULL;

	add_alloc(mem);
}

void temp_mempool_init(void)
{
        stack_counter = 0;
	current_stack = NULL;
	buffer_mem = NULL;

	t_push();
}

void temp_mempool_deinit(void)
{
	t_pop();

	if (stack_counter != 0)
		i_panic("Missing t_pop() call");
}

#endif
