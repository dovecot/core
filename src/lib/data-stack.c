/*
 data-stack.c : Data stack implementation

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

/* @UNSAFE: whole file */

#include "lib.h"
#include "data-stack.h"

#include <stdlib.h>

/* Use malloc() and free() for all memory allocations. Useful for debugging
   memory corruption. */
/* #define DISABLE_DATA_STACK */

#ifndef DISABLE_DATA_STACK

/* Initial stack size - this should be kept in a size that doesn't exceed
   in a normal use to avoid extra malloc()ing. */
#ifdef DEBUG
#  define INITIAL_STACK_SIZE (1024*10)
#else
#  define INITIAL_STACK_SIZE (1024*32)
#endif

typedef struct _StackBlock StackBlock;
typedef struct _StackFrameBlock StackFrameBlock;

struct _StackBlock {
	StackBlock *next;

	size_t size, left;
	/* unsigned char data[]; */
};

#define SIZEOF_MEMBLOCK MEM_ALIGN(sizeof(StackBlock))

#define STACK_BLOCK_DATA(block) \
	((char *) (block) + SIZEOF_MEMBLOCK)

/* current_frame_block contains last t_push()ed frames. After that new
   StackFrameBlock is created and it's ->prev is set to current_frame_block. */
#define BLOCK_FRAME_COUNT 32

struct _StackFrameBlock {
	StackFrameBlock *prev;

	StackBlock *block[BLOCK_FRAME_COUNT];
        size_t block_space_used[BLOCK_FRAME_COUNT];
	size_t last_alloc_size[BLOCK_FRAME_COUNT];
};

unsigned int data_stack_frame;

static int frame_pos; /* current frame position current_frame_block */
static StackFrameBlock *current_frame_block; /* current stack frame block */
static StackFrameBlock *unused_frame_blocks; /* unused stack frames */

static StackBlock *current_block; /* block currently used for allocation */
static StackBlock *unused_block; /* largest unused block is kept here */

static StackBlock *last_buffer_block;
static size_t last_buffer_size;

unsigned int t_push(void)
{
        StackFrameBlock *frame_block;

	frame_pos++;
	if (frame_pos == BLOCK_FRAME_COUNT) {
		/* frame block full */
		frame_pos = 0;
		if (unused_frame_blocks == NULL) {
			/* allocate new block */
			frame_block = calloc(sizeof(StackFrameBlock), 1);
			if (frame_block == NULL)
				i_panic("t_push(): Out of memory");
		} else {
			/* use existing unused frame_block */
			frame_block = unused_frame_blocks;
			unused_frame_blocks = unused_frame_blocks->prev;
		}

		frame_block->prev = current_frame_block;
		current_frame_block = frame_block;
	}

	/* mark our current position */
	current_frame_block->block[frame_pos] = current_block;
	current_frame_block->block_space_used[frame_pos] = current_block->left;
        current_frame_block->last_alloc_size[frame_pos] = 0;

        return data_stack_frame++;
}

static void free_blocks(StackBlock *block)
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

unsigned int t_pop(void)
{
	StackFrameBlock *frame_block;
	int popped_frame_pos;

	if (frame_pos < 0)
		i_panic("t_pop() called with empty stack");

	/* update the current block */
	current_block = current_frame_block->block[frame_pos];
	current_block->left = current_frame_block->block_space_used[frame_pos];
#ifdef DEBUG
	memset(STACK_BLOCK_DATA(current_block) +
	       (current_block->size - current_block->left), 0xde,
	       current_block->left);
#endif
	if (current_block->next != NULL) {
		/* free unused blocks */
		free_blocks(current_block->next);
		current_block->next = NULL;
	}

	popped_frame_pos = frame_pos;
	if (frame_pos > 0)
		frame_pos--;
	else {
		/* frame block is now unused, add it to unused list */
		frame_pos = BLOCK_FRAME_COUNT-1;

		frame_block = current_frame_block;
		current_frame_block = frame_block->prev;

		frame_block->prev = unused_frame_blocks;
		unused_frame_blocks = frame_block;
	}

        return --data_stack_frame;
}

static StackBlock *mem_block_alloc(size_t min_size)
{
	StackBlock *block;
	size_t prev_size, alloc_size;

	prev_size = current_block == NULL ? 0 : current_block->size;
	alloc_size = nearest_power(prev_size + min_size);

	block = malloc(SIZEOF_MEMBLOCK + alloc_size);
	if (block == NULL) {
		i_panic("mem_block_alloc(): "
			"Out of memory when allocating %"PRIuSIZE_T" bytes",
			alloc_size + SIZEOF_MEMBLOCK);
	}
	block->size = alloc_size;
	block->next = NULL;

	return block;
}

static void *t_malloc_real(size_t size, int permanent)
{
	StackBlock *block;
        void *ret;
#ifdef DEBUG
	int warn = FALSE;
#endif

	if (size == 0 || size > SSIZE_T_MAX)
		i_panic("Trying to allocate %"PRIuSIZE_T" bytes", size);

	/* reset t_buffer_get() mark - not really needed but makes it easier
	   to notice if t_malloc() is called between t_buffer_get() and
	   t_buffer_alloc() */
        last_buffer_block = NULL;

	/* allocate only aligned amount of memory so alignment comes
	   always properly */
	size = MEM_ALIGN(size);

	/* used for t_try_realloc() */
	current_frame_block->last_alloc_size[frame_pos] = size;

	if (current_block->left >= size) {
		/* enough space in current block, use it */
		ret = STACK_BLOCK_DATA(current_block) +
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
#ifdef DEBUG
		warn = TRUE;
#endif
	}

	block->left = block->size;
	if (permanent)
		block->left -= size;
	block->next = NULL;

	current_block->next = block;
	current_block = block;

	ret = STACK_BLOCK_DATA(current_block);
#ifdef DEBUG
	if (warn) {
		/* warn later, so that if i_warning() wants to allocate more
		   memory we don't go to infinite loop */
		i_warning("Growing data stack with: %"PRIuSIZE_T, block->size);
	}
#endif

        return ret;
}

void *t_malloc(size_t size)
{
        return t_malloc_real(size, TRUE);
}

void *t_malloc0(size_t size)
{
	void *mem;

	mem = t_malloc_real(size, TRUE);
	memset(mem, 0, size);
        return mem;
}

int t_try_realloc(void *mem, size_t size)
{
	size_t last_alloc_size;

	if (size == 0 || size > SSIZE_T_MAX)
		i_panic("Trying to allocate %"PRIuSIZE_T" bytes", size);

	last_alloc_size = current_frame_block->last_alloc_size[frame_pos];

	/* see if we're trying to grow the memory we allocated last */
	if (STACK_BLOCK_DATA(current_block) +
	    (current_block->size - current_block->left -
	     last_alloc_size) == mem) {
		/* yeah, see if we have space to grow */
		size = MEM_ALIGN(size);
		if (current_block->left >= size - last_alloc_size) {
			/* just shrink the available size */
			current_block->left -= size - last_alloc_size;
			current_frame_block->last_alloc_size[frame_pos] = size;
			return TRUE;
		}
	}

	return FALSE;
}

void *t_buffer_get(size_t size)
{
	void *ret;

	ret = t_malloc_real(size, FALSE);

	last_buffer_size = size;
	last_buffer_block = current_block;
	return ret;
}

void *t_buffer_reget(void *buffer, size_t size)
{
	size_t old_size;
        void *new_buffer;

	old_size = last_buffer_size;
	if (size <= old_size)
                return buffer;

	new_buffer = t_buffer_get(size);
	if (new_buffer != buffer)
                memcpy(new_buffer, buffer, old_size);

        return new_buffer;
}

void t_buffer_alloc(size_t size)
{
	i_assert(last_buffer_block != NULL);
	i_assert(last_buffer_size >= size);
	i_assert(current_block->left >= size);

	/* we've already reserved the space, now we just mark it used */
	t_malloc_real(size, TRUE);
}

void data_stack_init(void)
{
        data_stack_frame = 0;

	current_block = mem_block_alloc(INITIAL_STACK_SIZE);
	current_block->left = current_block->size;
	current_block->next = NULL;

	current_frame_block = NULL;
	unused_frame_blocks = NULL;
	frame_pos = BLOCK_FRAME_COUNT-1;

	t_push();

        last_buffer_block = NULL;
	last_buffer_size = 0;
}

void data_stack_deinit(void)
{
	t_pop();

	if (frame_pos != BLOCK_FRAME_COUNT-1)
		i_panic("Missing t_pop() call");

	while (unused_frame_blocks != NULL) {
                StackFrameBlock *frame_block = unused_frame_blocks;
		unused_frame_blocks = unused_frame_blocks->prev;

                free(frame_block);
	}

	free(current_block);
	free(unused_block);
}

#else

typedef struct _StackFrame StackFrame;
typedef struct _FrameAlloc FrameAlloc;

struct _StackFrame {
	StackFrame *next;
	FrameAlloc *allocs;
};

struct _FrameAlloc {
	FrameAlloc *next;
	void *mem;
};

unsigned int data_stack_frame;

static StackFrame *current_frame;
static void *buffer_mem;

unsigned int t_push(void)
{
	StackFrame *frame;

	frame = malloc(sizeof(StackFrame));
	if (frame == NULL)
		i_panic("t_push(): Out of memory");
	frame->allocs = NULL;

	frame->next = current_frame;
	current_frame = frame;
	return data_stack_frame++;
}

unsigned int t_pop(void)
{
	StackFrame *frame;
	FrameAlloc *alloc;

	frame = current_frame;
	current_frame = frame->next;

	while (frame->allocs != NULL) {
		alloc = frame->allocs;
		frame->allocs = alloc->next;

		free(alloc->mem);
		free(alloc);
	}

	free(frame);
	return --data_stack_frame;
}

static void add_alloc(void *mem)
{
	FrameAlloc *alloc;

	alloc = malloc(sizeof(FrameAlloc));
	if (alloc == NULL)
		i_panic("add_alloc(): Out of memory");
	alloc->mem = mem;
	alloc->next = current_frame->allocs;
	current_frame->allocs = alloc;

	if (buffer_mem != NULL) {
		free(buffer_mem);
		buffer_mem = NULL;
	}
}

void *t_malloc(size_t size)
{
	void *mem;

	mem = malloc(size);
	if (mem == NULL)
		i_panic("t_malloc(): Out of memory");
	add_alloc(mem);
	return mem;
}

void *t_malloc0(size_t size)
{
	void *mem;

	mem = calloc(size, 1);
	if (mem == NULL)
		i_panic("t_malloc0(): Out of memory");
	add_alloc(mem);
	return mem;
}

int t_try_realloc(void *mem __attr_unused__, size_t size __attr_unused__)
{
	return FALSE;
}

void *t_buffer_get(size_t size)
{
	buffer_mem = realloc(buffer_mem, size);
	if (buffer_mem == NULL)
		i_panic("t_buffer_get(): Out of memory");
	return buffer_mem;
}

void *t_buffer_reget(void *buffer, size_t size)
{
	i_assert(buffer == buffer_mem);

	buffer_mem = realloc(buffer_mem, size);
	if (buffer_mem == NULL)
		i_panic("t_buffer_reget(): Out of memory");
	return buffer_mem;
}

void t_buffer_alloc(size_t size)
{
	void *mem;

	i_assert(buffer_mem != NULL);

	mem = realloc(buffer_mem, size);
	if (mem == NULL)
		i_panic("t_buffer_alloc(): Out of memory");
	buffer_mem = NULL;

	add_alloc(mem);
}

void data_stack_init(void)
{
        data_stack_frame = 0;
	current_frame = NULL;
	buffer_mem = NULL;

	t_push();
}

void data_stack_deinit(void)
{
	t_pop();

	if (data_stack_frame != 0)
		i_panic("Missing t_pop() call");
}

#endif
