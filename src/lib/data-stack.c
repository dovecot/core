/* Copyright (c) 2002-2007 Dovecot authors, see the included COPYING file */

/* @UNSAFE: whole file */

#include "lib.h"
#include "data-stack.h"

#include <stdlib.h>

#ifdef HAVE_GC_GC_H
#  include <gc/gc.h>
#elif defined (HAVE_GC_H)
#  include <gc.h>
#endif

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

#ifdef DEBUG
#  define CLEAR_CHR 0xde
#else
#  define CLEAR_CHR 0
#endif

struct stack_block {
	struct stack_block *next;

	size_t size, left;
	/* unsigned char data[]; */
};

#define SIZEOF_MEMBLOCK MEM_ALIGN(sizeof(struct stack_block))

#define STACK_BLOCK_DATA(block) \
	((char *) (block) + SIZEOF_MEMBLOCK)

/* current_frame_block contains last t_push()ed frames. After that new
   stack_frame_block is created and it's ->prev is set to
   current_frame_block. */
#define BLOCK_FRAME_COUNT 32

struct stack_frame_block {
	struct stack_frame_block *prev;

	struct stack_block *block[BLOCK_FRAME_COUNT];
        size_t block_space_used[BLOCK_FRAME_COUNT];
	size_t last_alloc_size[BLOCK_FRAME_COUNT];
};

unsigned int data_stack_frame = 0;

static int frame_pos = BLOCK_FRAME_COUNT-1; /* in current_frame_block */
static struct stack_frame_block *current_frame_block;
static struct stack_frame_block *unused_frame_blocks;

static struct stack_block *current_block; /* block now used for allocation */
static struct stack_block *unused_block; /* largest unused block is kept here */

static struct stack_block *last_buffer_block;
static size_t last_buffer_size;
static bool clean_after_pop = FALSE;
static bool outofmem = FALSE;

union {
	struct stack_block block;
	unsigned char data[128];
} outofmem_area;

unsigned int t_push(void)
{
        struct stack_frame_block *frame_block;

	frame_pos++;
	if (frame_pos == BLOCK_FRAME_COUNT) {
		/* frame block full */
		if (data_stack_frame == 0) {
			/* kludgy, but allow this before initialization */
			frame_pos = 0;
			data_stack_init();
			return t_push();
		}

		frame_pos = 0;
		if (unused_frame_blocks == NULL) {
			/* allocate new block */
#ifndef USE_GC
			frame_block = calloc(sizeof(*frame_block), 1);
#else
			frame_block = GC_malloc(sizeof(*frame_block));
#endif
			if (frame_block == NULL) {
				i_fatal_status(FATAL_OUTOFMEM,
					       "t_push(): Out of memory");
			}
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

static void free_blocks(struct stack_block *block)
{
	struct stack_block *next;

	/* free all the blocks, except if any of them is bigger than
	   unused_block, replace it */
	while (block != NULL) {
		next = block->next;

		if (unused_block == NULL || block->size > unused_block->size) {
			if (clean_after_pop) {
				memset(STACK_BLOCK_DATA(unused_block),
				       CLEAR_CHR, unused_block->size);
			}
#ifndef USE_GC
			free(unused_block);
#endif
			unused_block = block;
		} else {
			if (clean_after_pop) {
				memset(STACK_BLOCK_DATA(block), CLEAR_CHR,
				       block->size);
			}
#ifndef USE_GC
			free(block);
#endif
		}

		block = next;
	}
}

unsigned int t_pop(void)
{
	struct stack_frame_block *frame_block;
	int popped_frame_pos;

	if (unlikely(frame_pos < 0))
		i_panic("t_pop() called with empty stack");

	/* update the current block */
	current_block = current_frame_block->block[frame_pos];
	current_block->left = current_frame_block->block_space_used[frame_pos];
	if (clean_after_pop) {
		memset(STACK_BLOCK_DATA(current_block) +
		       (current_block->size - current_block->left), CLEAR_CHR,
		       current_block->left);
	}
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

static struct stack_block *mem_block_alloc(size_t min_size)
{
	struct stack_block *block;
	size_t prev_size, alloc_size;

	prev_size = current_block == NULL ? 0 : current_block->size;
	alloc_size = nearest_power(prev_size + min_size);

#ifndef USE_GC
	block = malloc(SIZEOF_MEMBLOCK + alloc_size);
#else
	block = GC_malloc(SIZEOF_MEMBLOCK + alloc_size);
#endif
	if (unlikely(block == NULL)) {
		if (outofmem) {
			if (min_size > outofmem_area.block.left)
				abort();
			return &outofmem_area.block;
		}
		outofmem = TRUE;
		i_panic("data stack: Out of memory when allocating %"
			PRIuSIZE_T" bytes", alloc_size + SIZEOF_MEMBLOCK);
	}
	block->size = alloc_size;
	block->next = NULL;

	return block;
}

static void *t_malloc_real(size_t size, bool permanent)
{
	struct stack_block *block;
        void *ret;
#ifdef DEBUG
	bool warn = FALSE;
#endif

	if (unlikely(size == 0 || size > SSIZE_T_MAX))
		i_panic("Trying to allocate %"PRIuSIZE_T" bytes", size);

	if (unlikely(data_stack_frame == 0)) {
		/* kludgy, but allow this before initialization */
		data_stack_init();
	}

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

bool t_try_realloc(void *mem, size_t size)
{
	size_t last_alloc_size;

	if (unlikely(size == 0 || size > SSIZE_T_MAX))
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

size_t t_get_bytes_available(void)
{
	return current_block->left;
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

void data_stack_set_clean_after_pop(bool enable)
{
	clean_after_pop = enable;
}

void data_stack_init(void)
{
	if (data_stack_frame == 0) {
		data_stack_frame = 1;

		outofmem_area.block.size = outofmem_area.block.left =
			sizeof(outofmem_area) - sizeof(outofmem_area.block);

		current_block = mem_block_alloc(INITIAL_STACK_SIZE);
		current_block->left = current_block->size;
		current_block->next = NULL;

		current_frame_block = NULL;
		unused_frame_blocks = NULL;
		frame_pos = BLOCK_FRAME_COUNT-1;

		last_buffer_block = NULL;
		last_buffer_size = 0;
	}

	t_push();
}

void data_stack_deinit(void)
{
	t_pop();

	if (frame_pos != BLOCK_FRAME_COUNT-1)
		i_panic("Missing t_pop() call");

#ifndef USE_GC
	while (unused_frame_blocks != NULL) {
                struct stack_frame_block *frame_block = unused_frame_blocks;
		unused_frame_blocks = unused_frame_blocks->prev;

		free(frame_block);
	}

	free(current_block);
	free(unused_block);
#endif
	unused_frame_blocks = NULL;
	current_block = NULL;
	unused_block = NULL;
}

#else

#ifdef USE_GC
#  error No GC with disabled data stack
#endif

struct stack_frame {
	struct stack_frame *next;
	struct frame_alloc *allocs;
};

struct frame_alloc {
	struct frame_alloc *next;
	void *mem;
};

unsigned int data_stack_frame;

static struct stack_frame *current_frame;
static void *buffer_mem;

unsigned int t_push(void)
{
	struct stack_frame *frame;

	frame = malloc(sizeof(struct stack_frame));
	if (frame == NULL)
		i_panic("t_push(): Out of memory");
	frame->allocs = NULL;

	frame->next = current_frame;
	current_frame = frame;
	return data_stack_frame++;
}

unsigned int t_pop(void)
{
	struct stack_frame *frame;
	struct frame_alloc *alloc;

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
	struct frame_alloc *alloc;

	alloc = malloc(sizeof(struct frame_alloc));
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

bool t_try_realloc(void *mem ATTR_UNUSED, size_t size ATTR_UNUSED)
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

#ifdef DEBUG
	clean_after_pop = TRUE;
#endif
	t_push();
}

void data_stack_deinit(void)
{
	t_pop();

	if (data_stack_frame != 0)
		i_panic("Missing t_pop() call");
}

#endif
