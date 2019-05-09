/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

/* @UNSAFE: whole file */

#include "lib.h"
#include "data-stack.h"


/* Initial stack size - this should be kept in a size that doesn't exceed
   in a normal use to avoid extra malloc()ing. */
#ifdef DEBUG
#  define INITIAL_STACK_SIZE (1024*10)
#else
#  define INITIAL_STACK_SIZE (1024*32)
#endif

#ifdef DEBUG
#  define CLEAR_CHR 0xD5               /* D5 is mnemonic for "Data 5tack" */
#  define SENTRY_COUNT (4*8)
#  define BLOCK_CANARY ((void *)0xBADBADD5BADBADD5)      /* contains 'D5' */
#  define ALLOC_SIZE(size) (MEM_ALIGN(sizeof(size_t)) + MEM_ALIGN(size + SENTRY_COUNT))
#else
#  define CLEAR_CHR 0
#  define BLOCK_CANARY NULL
#  define block_canary_check(block) do { ; } while(0)
#  define ALLOC_SIZE(size) MEM_ALIGN(size)
#endif

struct stack_block {
	struct stack_block *next;

	size_t size, left, lowwater;
	/* NULL or a poison value, just in case something accesses
	   the memory in front of an allocated area */
	void *canary;
	unsigned char data[FLEXIBLE_ARRAY_MEMBER];
};

#define SIZEOF_MEMBLOCK MEM_ALIGN(sizeof(struct stack_block))

#define STACK_BLOCK_DATA(block) \
	(block->data + (SIZEOF_MEMBLOCK - sizeof(struct stack_block)))

/* current_frame_block contains last t_push()ed frames. After that new
   stack_frame_block is created and it's ->prev is set to
   current_frame_block. */
#define BLOCK_FRAME_COUNT 32

struct stack_frame_block {
	struct stack_frame_block *prev;

	struct stack_block *block[BLOCK_FRAME_COUNT];
	size_t block_space_used[BLOCK_FRAME_COUNT];
	size_t last_alloc_size[BLOCK_FRAME_COUNT];
	const char *marker[BLOCK_FRAME_COUNT];
#ifdef DEBUG
	/* Fairly arbitrary profiling data */
	unsigned long long alloc_bytes[BLOCK_FRAME_COUNT];
	unsigned int alloc_count[BLOCK_FRAME_COUNT];
#endif
};

#ifdef STATIC_CHECKER
struct data_stack_frame {
	unsigned int id;
};
#endif

unsigned int data_stack_frame_id = 0;

static bool data_stack_initialized = FALSE;
static data_stack_frame_t root_frame_id;

static int frame_pos = BLOCK_FRAME_COUNT-1; /* in current_frame_block */
static struct stack_frame_block *current_frame_block;
static struct stack_frame_block *unused_frame_blocks;

static struct stack_block *current_block; /* block now used for allocation */
static struct stack_block *unused_block; /* largest unused block is kept here */

static struct stack_block *last_buffer_block;
static size_t last_buffer_size;
#ifdef DEBUG
static bool clean_after_pop = TRUE;
#else
static bool clean_after_pop = FALSE;
#endif
static bool outofmem = FALSE;

static union {
	struct stack_block block;
	unsigned char data[512];
} outofmem_area;

static struct stack_block *mem_block_alloc(size_t min_size);

static inline
unsigned char *data_stack_after_last_alloc(struct stack_block *block)
{
	return STACK_BLOCK_DATA(block) + (block->size - block->left);
}

static void data_stack_last_buffer_reset(bool preserve_data ATTR_UNUSED)
{
	if (last_buffer_block != NULL) {
#ifdef DEBUG
		unsigned char *last_alloc_end, *p, *pend;

		last_alloc_end = data_stack_after_last_alloc(current_block);
		p = last_alloc_end + MEM_ALIGN(sizeof(size_t)) + last_buffer_size;
		pend = last_alloc_end + ALLOC_SIZE(last_buffer_size);
#endif
		/* reset t_buffer_get() mark - not really needed but makes it
		   easier to notice if t_malloc()/t_push()/t_pop() is called
		   between t_buffer_get() and t_buffer_alloc().
		   do this before we get to i_panic() to avoid recursive
		   panics. */
		last_buffer_block = NULL;

#ifdef DEBUG
		while (p < pend)
			if (*p++ != CLEAR_CHR)
				i_panic("t_buffer_get(): buffer overflow");

		if (!preserve_data) {
			p = last_alloc_end;
			memset(p, CLEAR_CHR, SENTRY_COUNT);
		}
#endif
	}
}

data_stack_frame_t t_push(const char *marker)
{
	struct stack_frame_block *frame_block;

	frame_pos++;
	if (frame_pos == BLOCK_FRAME_COUNT) {
		/* frame block full */
		if (unlikely(!data_stack_initialized)) {
			/* kludgy, but allow this before initialization */
			frame_pos = 0;
			data_stack_init();
			return t_push(marker);
		}

		frame_pos = 0;
		if (unused_frame_blocks == NULL) {
			/* allocate new block */
			frame_block = calloc(sizeof(*frame_block), 1);
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
	current_frame_block->marker[frame_pos] = marker;
#ifdef DEBUG
	current_frame_block->alloc_bytes[frame_pos] = 0ULL;
	current_frame_block->alloc_count[frame_pos] = 0;
#endif

#ifndef STATIC_CHECKER
	return data_stack_frame_id++;
#else
	struct data_stack_frame *frame = i_new(struct data_stack_frame, 1);
	frame->id = data_stack_frame_id++;
	return frame;
#endif
}

data_stack_frame_t t_push_named(const char *format, ...)
{
	data_stack_frame_t ret = t_push(NULL);
#ifdef DEBUG
	va_list args;
	va_start(args, format);
	current_frame_block->marker[frame_pos] = p_strdup_vprintf(unsafe_data_stack_pool, format, args);
	va_end(args);
#else
	(void)format; /* unused in non-DEBUG builds */
#endif

	return ret;
}

#ifdef DEBUG
static void block_canary_check(struct stack_block *block)
{
	if (block->canary != BLOCK_CANARY) {
		/* Make sure i_panic() won't try to allocate from the
		   same block by falling back onto our emergency block. */
		current_block = &outofmem_area.block;
		i_panic("Corrupted data stack canary");
	}
}
#endif

static void free_blocks(struct stack_block *block)
{
	struct stack_block *next;

	/* free all the blocks, except if any of them is bigger than
	   unused_block, replace it */
	while (block != NULL) {
		block_canary_check(block);
		next = block->next;

		if (clean_after_pop)
			memset(STACK_BLOCK_DATA(block), CLEAR_CHR, block->size);

		if (unused_block == NULL || block->size > unused_block->size) {
			free(unused_block);
			unused_block = block;
		} else {
			if (block != &outofmem_area.block)
				free(block);
		}

		block = next;
	}
}

#ifdef DEBUG
static void t_pop_verify(void)
{
	struct stack_block *block;
	unsigned char *p;
	size_t pos, max_pos, used_size;

	block = current_frame_block->block[frame_pos];
	pos = block->size - current_frame_block->block_space_used[frame_pos];
	while (block != NULL) {
		block_canary_check(block);
		used_size = block->size - block->left;
		p = STACK_BLOCK_DATA(block);
		while (pos < used_size) {
			size_t requested_size = *(size_t *)(p + pos);
			if (used_size - pos < requested_size)
				i_panic("data stack[%s]: saved alloc size broken",
					current_frame_block->marker[frame_pos]);
			max_pos = pos + ALLOC_SIZE(requested_size);
			pos += MEM_ALIGN(sizeof(size_t)) + requested_size;

			for (; pos < max_pos; pos++) {
				if (p[pos] != CLEAR_CHR)
					i_panic("data stack[%s]: buffer overflow",
						current_frame_block->marker[frame_pos]);
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

void t_pop_last_unsafe(void)
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
	block_canary_check(current_block);
	if (clean_after_pop) {
		size_t pos, used_size;

		pos = current_block->size -
			current_frame_block->block_space_used[frame_pos];
		used_size = current_block->size - current_block->lowwater;
		i_assert(used_size >= pos);
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
	data_stack_frame_id--;
}

bool t_pop(data_stack_frame_t *id)
{
	t_pop_last_unsafe();
#ifndef STATIC_CHECKER
	if (unlikely(data_stack_frame_id != *id))
		return FALSE;
	*id = 0;
#else
	unsigned int frame_id = (*id)->id;
	i_free_and_null(*id);

	if (unlikely(data_stack_frame_id != frame_id))
		return FALSE;
#endif
	return TRUE;
}

static struct stack_block *mem_block_alloc(size_t min_size)
{
	struct stack_block *block;
	size_t prev_size, alloc_size;

	prev_size = current_block == NULL ? 0 : current_block->size;
	alloc_size = nearest_power(MALLOC_ADD(prev_size, min_size));

	/* nearest_power() returns 2^n values, so alloc_size can't be
	   anywhere close to SIZE_MAX */
	block = malloc(SIZEOF_MEMBLOCK + alloc_size);
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
	block->canary = BLOCK_CANARY;

#ifdef DEBUG
	memset(STACK_BLOCK_DATA(block), CLEAR_CHR, alloc_size);
#endif
	return block;
}

static void *t_malloc_real(size_t size, bool permanent)
{
	void *ret;
	size_t alloc_size;
#ifdef DEBUG
	bool warn = FALSE;
	int old_errno = errno;
#endif

	if (unlikely(size == 0 || size > SSIZE_T_MAX))
		i_panic("Trying to allocate %"PRIuSIZE_T" bytes", size);

	if (unlikely(!data_stack_initialized)) {
		/* kludgy, but allow this before initialization */
		data_stack_init();
	}
	block_canary_check(current_block);

	/* allocate only aligned amount of memory so alignment comes
	   always properly */
	alloc_size = ALLOC_SIZE(size);
#ifdef DEBUG
	if(permanent) {
		current_frame_block->alloc_bytes[frame_pos] += alloc_size;
		current_frame_block->alloc_count[frame_pos]++;
	}
#endif
	data_stack_last_buffer_reset(TRUE);

	/* used for t_try_realloc() */
	current_frame_block->last_alloc_size[frame_pos] = alloc_size;

	if (current_block->left < alloc_size) {
		struct stack_block *block;

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
		block->next = NULL;
		current_block->next = block;
		current_block = block;
	}

	/* enough space in current block, use it */
	ret = data_stack_after_last_alloc(current_block);

	if (current_block->left - alloc_size < current_block->lowwater)
		current_block->lowwater = current_block->left - alloc_size;
	if (permanent)
		current_block->left -= alloc_size;

#ifdef DEBUG
	if (warn && getenv("DEBUG_SILENT") == NULL) {
		/* warn after allocation, so if i_debug() wants to
		   allocate more memory we don't go to infinite loop */
		i_debug("Growing data stack by %zu as "
			  "'%s' reaches %llu bytes from %u allocations.",
			  current_block->size,
			  current_frame_block->marker[frame_pos],
			  current_frame_block->alloc_bytes[frame_pos],
			  current_frame_block->alloc_count[frame_pos]);
	}
	memcpy(ret, &size, sizeof(size));
	ret = PTR_OFFSET(ret, MEM_ALIGN(sizeof(size)));
	/* make sure the sentry contains CLEAR_CHRs. it might not if we
	   had used t_buffer_get(). */
	memset(PTR_OFFSET(ret, size), CLEAR_CHR,
	       MEM_ALIGN(size + SENTRY_COUNT) - size);

	/* we rely on errno not changing. it shouldn't. */
	i_assert(errno == old_errno);
#endif
	return ret;
}

void *t_malloc_no0(size_t size)
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
	size_t debug_adjust = 0, last_alloc_size;
	unsigned char *after_last_alloc;

	if (unlikely(size == 0 || size > SSIZE_T_MAX))
		i_panic("Trying to allocate %"PRIuSIZE_T" bytes", size);
	block_canary_check(current_block);

	last_alloc_size = current_frame_block->last_alloc_size[frame_pos];

	/* see if we're trying to grow the memory we allocated last */
	after_last_alloc = data_stack_after_last_alloc(current_block);
#ifdef DEBUG
	debug_adjust = MEM_ALIGN(sizeof(size_t));
#endif
	if (after_last_alloc - last_alloc_size + debug_adjust == mem) {
		/* yeah, see if we have space to grow */
		size_t new_alloc_size, alloc_growth;

		new_alloc_size = ALLOC_SIZE(size);
		alloc_growth = (new_alloc_size - last_alloc_size);
#ifdef DEBUG
		size_t old_raw_size; /* sorry, non-C99 users - add braces if you need them */
		old_raw_size = *(size_t *)PTR_OFFSET(mem, -(ptrdiff_t)MEM_ALIGN(sizeof(size_t)));
		i_assert(ALLOC_SIZE(old_raw_size) == last_alloc_size);
		/* Only check one byte for over-run, that catches most
		   offenders who are likely to use t_try_realloc() */
		i_assert(((unsigned char*)mem)[old_raw_size] == CLEAR_CHR);
#endif

		if (current_block->left >= alloc_growth) {
			/* just shrink the available size */
			current_block->left -= alloc_growth;
			if (current_block->left < current_block->lowwater)
				current_block->lowwater = current_block->left;
			current_frame_block->last_alloc_size[frame_pos] =
				new_alloc_size;
#ifdef DEBUG
			/* All reallocs are permanent by definition
			   However, they don't count as a new allocation */
			current_frame_block->alloc_bytes[frame_pos] += alloc_growth;
			*(size_t *)PTR_OFFSET(mem, -(ptrdiff_t)MEM_ALIGN(sizeof(size_t))) = size;
			memset(PTR_OFFSET(mem, size), CLEAR_CHR,
			       new_alloc_size - size - MEM_ALIGN(sizeof(size_t)));
#endif
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
	block_canary_check(current_block);
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
	(void)t_malloc_real(size, TRUE);
}

void t_buffer_alloc_last_full(void)
{
	if (last_buffer_block != NULL)
		(void)t_malloc_real(last_buffer_size, TRUE);
}

void data_stack_set_clean_after_pop(bool enable ATTR_UNUSED)
{
#ifndef DEBUG
	clean_after_pop = enable;
#endif
}

void data_stack_init(void)
{
	if (data_stack_initialized) {
		/* already initialized (we did auto-initialization in
		   t_malloc/t_push) */
		return;
	}
	data_stack_initialized = TRUE;
	data_stack_frame_id = 1;

	outofmem_area.block.size = outofmem_area.block.left =
		sizeof(outofmem_area) - sizeof(outofmem_area.block);
	outofmem_area.block.canary = BLOCK_CANARY;

	current_block = mem_block_alloc(INITIAL_STACK_SIZE);
	current_block->left = current_block->size;
	current_block->next = NULL;

	current_frame_block = NULL;
	unused_frame_blocks = NULL;
	frame_pos = BLOCK_FRAME_COUNT-1;

	last_buffer_block = NULL;
	last_buffer_size = 0;

	root_frame_id = t_push("data_stack_init");
}

void data_stack_deinit(void)
{
	if (!t_pop(&root_frame_id) ||
	    frame_pos != BLOCK_FRAME_COUNT-1)
		i_panic("Missing t_pop() call");

	while (unused_frame_blocks != NULL) {
		struct stack_frame_block *frame_block = unused_frame_blocks;
		unused_frame_blocks = unused_frame_blocks->prev;

		free(frame_block);
	}

	free(current_block);
	free(unused_block);
	unused_frame_blocks = NULL;
	current_block = NULL;
	unused_block = NULL;
}
