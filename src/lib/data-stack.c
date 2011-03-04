/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

/* @UNSAFE: whole file */

#include "lib.h"
#include "data-stack.h"

#include <stdlib.h>

#ifdef HAVE_GC_GC_H
#  include <gc/gc.h>
#elif defined (HAVE_GC_H)
#  include <gc.h>
#endif

/* Initial stack size - this should be kept in a size that doesn't exceed
   in a normal use to avoid extra malloc()ing. */
#ifdef DEBUG
#  define INITIAL_STACK_SIZE (1024*10)
#else
#  define INITIAL_STACK_SIZE (1024*32)
#endif

#ifdef DEBUG
#  define CLEAR_CHR 0xde
#  define SENTRY_COUNT (4*8)
#else
#  define CLEAR_CHR 0
#endif

struct stack_block {
	struct stack_block *next;

	size_t size, left, lowwater;
	/* unsigned char data[]; */
};

#define SIZEOF_MEMBLOCK MEM_ALIGN(sizeof(struct stack_block))

#define STACK_BLOCK_DATA(block) \
	((unsigned char *) (block) + SIZEOF_MEMBLOCK)

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

static union {
	struct stack_block block;
	unsigned char data[512];
} outofmem_area;

static void data_stack_last_buffer_reset(bool preserve_data ATTR_UNUSED)
{
	if (last_buffer_block != NULL) {
#ifdef DEBUG
		unsigned char *p;
		unsigned int i;

		p = STACK_BLOCK_DATA(current_block) +
			(current_block->size - current_block->left) +
			MEM_ALIGN(sizeof(size_t)) + MEM_ALIGN(last_buffer_size);
#endif
		/* reset t_buffer_get() mark - not really needed but makes it
		   easier to notice if t_malloc()/t_push()/t_pop() is called
		   between t_buffer_get() and t_buffer_alloc().
		   do this before we get to i_panic() to avoid recursive
		   panics. */
		last_buffer_block = NULL;

#ifdef DEBUG
		for (i = 0; i < SENTRY_COUNT; i++) {
			if (p[i] != CLEAR_CHR)
				i_panic("t_buffer_get(): buffer overflow");
		}

		if (!preserve_data) {
			p = STACK_BLOCK_DATA(current_block) +
				(current_block->size - current_block->left);
			memset(p, CLEAR_CHR, SENTRY_COUNT);
		}
#endif
	}
}

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
	data_stack_last_buffer_reset(FALSE);

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

		if (clean_after_pop)
			memset(STACK_BLOCK_DATA(block), CLEAR_CHR, block->size);

		if (unused_block == NULL || block->size > unused_block->size) {
#ifndef USE_GC
			free(unused_block);
#endif
			unused_block = block;
		} else {
#ifndef USE_GC
			if (block != &outofmem_area.block)
				free(block);
#endif
		}

		block = next;
	}
}

#ifdef DEBUG
static void t_pop_verify(void)
{
	struct stack_block *block;
	unsigned char *p;
	size_t pos, max_pos, used_size, alloc_size;

	block = current_frame_block->block[frame_pos];
	pos = block->size - current_frame_block->block_space_used[frame_pos];
	while (block != NULL) {
		used_size = block->size - block->left;
		p = STACK_BLOCK_DATA(block);
		while (pos < used_size) {
			alloc_size = *(size_t *)(p + pos);
			if (used_size - pos < alloc_size)
				i_panic("data stack: saved alloc size broken");
			pos += MEM_ALIGN(sizeof(alloc_size));
			max_pos = pos + MEM_ALIGN(alloc_size + SENTRY_COUNT);
			pos += alloc_size;

			for (; pos < max_pos; pos++) {
				if (p[pos] != CLEAR_CHR)
					i_panic("data stack: buffer overflow");
			}
		}

		/* if we had used t_buffer_get(), the rest of the buffer
		   may not contain CLEAR_CHRs. but we've already checked all
		   the allocations, so there's no need to check them anyway. */
		block = block->next;
		pos = 0;
	}
}
#endif

unsigned int t_pop(void)
{
	struct stack_frame_block *frame_block;

	if (unlikely(frame_pos < 0))
		i_panic("t_pop() called with empty stack");

	data_stack_last_buffer_reset(FALSE);
#ifdef DEBUG
	t_pop_verify();
#endif

	/* update the current block */
	current_block = current_frame_block->block[frame_pos];
	if (clean_after_pop) {
		size_t pos, used_size;

		pos = current_block->size -
			current_frame_block->block_space_used[frame_pos];
		used_size = current_block->size - current_block->lowwater;
		memset(STACK_BLOCK_DATA(current_block) + pos, CLEAR_CHR,
		       used_size - pos);
	}
	current_block->left = current_frame_block->block_space_used[frame_pos];
	current_block->lowwater = current_block->left;

	if (current_block->next != NULL) {
		/* free unused blocks */
		free_blocks(current_block->next);
		current_block->next = NULL;
	}

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

void t_pop_check(unsigned int *id)
{
	if (unlikely(t_pop() != *id))
		i_panic("Leaked t_pop() call");
	*id = 0;
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
	block->left = 0;
	block->lowwater = block->size;
	block->next = NULL;

#ifdef DEBUG
	memset(STACK_BLOCK_DATA(block), CLEAR_CHR, alloc_size);
#endif
	return block;
}

static void *t_malloc_real(size_t size, bool permanent)
{
	struct stack_block *block;
	void *ret;
	size_t alloc_size;
#ifdef DEBUG
	bool warn = FALSE;
#endif

	if (unlikely(size == 0 || size > SSIZE_T_MAX))
		i_panic("Trying to allocate %"PRIuSIZE_T" bytes", size);

	if (unlikely(data_stack_frame == 0)) {
		/* kludgy, but allow this before initialization */
		data_stack_init();
	}

	/* allocate only aligned amount of memory so alignment comes
	   always properly */
#ifndef DEBUG
	alloc_size = MEM_ALIGN(size);
#else
	alloc_size = MEM_ALIGN(sizeof(size)) + MEM_ALIGN(size + SENTRY_COUNT);
#endif
	data_stack_last_buffer_reset(TRUE);

	/* used for t_try_realloc() */
	current_frame_block->last_alloc_size[frame_pos] = alloc_size;

	if (current_block->left >= alloc_size) {
		/* enough space in current block, use it */
		ret = STACK_BLOCK_DATA(current_block) +
			(current_block->size - current_block->left);

		if (current_block->left - alloc_size <
		    current_block->lowwater) {
			current_block->lowwater =
				current_block->left - alloc_size;
		}
                if (permanent)
			current_block->left -= alloc_size;
	} else {
		/* current block is full, see if we can use the unused_block */
		if (unused_block != NULL && unused_block->size >= alloc_size) {
			block = unused_block;
			unused_block = NULL;
		} else {
			block = mem_block_alloc(alloc_size);
#ifdef DEBUG
			warn = TRUE;
#endif
		}

		block->left = block->size;
		if (block->left - alloc_size < block->lowwater)
			block->lowwater = block->left - alloc_size;
		if (permanent)
			block->left -= alloc_size;
		block->next = NULL;

		current_block->next = block;
		current_block = block;

		ret = STACK_BLOCK_DATA(current_block);
#ifdef DEBUG
		if (warn) {
			/* warn after allocation, so if i_warning() wants to
			   allocate more memory we don't go to infinite loop */
			i_warning("Growing data stack with: %"PRIuSIZE_T,
				  block->size);
		}
#endif
	}
#ifdef DEBUG
	memcpy(ret, &size, sizeof(size));
	ret = PTR_OFFSET(ret, MEM_ALIGN(sizeof(size)));
	/* make sure the sentry contains CLEAR_CHRs. it might not if we
	   had used t_buffer_get(). */
	memset(PTR_OFFSET(ret, size), CLEAR_CHR,
	       MEM_ALIGN(size + SENTRY_COUNT) - size);
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
#ifndef DEBUG
	const unsigned int extra = MEM_ALIGN_SIZE-1;
#else
	const unsigned int extra = MEM_ALIGN_SIZE-1 + SENTRY_COUNT +
		MEM_ALIGN(sizeof(size_t));
#endif
	return current_block->left < extra ? current_block->left :
		current_block->left - extra;
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

void t_buffer_alloc_last_full(void)
{
	if (last_buffer_block != NULL)
		t_malloc_real(last_buffer_size, TRUE);
}

void data_stack_set_clean_after_pop(bool enable ATTR_UNUSED)
{
#ifndef DEBUG
	clean_after_pop = enable;
#endif
}

void data_stack_init(void)
{
#ifdef DEBUG
	clean_after_pop = TRUE;
#endif
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
