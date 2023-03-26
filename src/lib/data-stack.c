/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

/* @UNSAFE: whole file */

#include "lib.h"
#include "backtrace-string.h"
#include "str.h"
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
	struct stack_block *prev, *next;

	size_t size, left;
#ifdef DEBUG
	/* The lowest value that "left" has been in this block since it was
	   last popped. This is used to keep track which parts of the block
	   needs to be cleared if DEBUG is used. */
	size_t left_lowwater;
#endif
	/* NULL or a poison value, just in case something accesses
	   the memory in front of an allocated area */
	void *canary;
	unsigned char data[FLEXIBLE_ARRAY_MEMBER];
};

#define SIZEOF_MEMBLOCK MEM_ALIGN(sizeof(struct stack_block))

#define STACK_BLOCK_DATA(block) \
	(block->data + (SIZEOF_MEMBLOCK - sizeof(struct stack_block)))

struct stack_frame {
	struct stack_frame *prev;

	struct stack_block *block;
	/* Each frame initializes this to current_block->left, i.e. how much
	   free space is left in the block. So the frame's start position in
	   the block is (block.size - block_space_left) */
	size_t block_space_left;
	size_t last_alloc_size;
	const char *marker;
#ifdef DEBUG
	/* Fairly arbitrary profiling data */
	unsigned long long alloc_bytes;
	unsigned int alloc_count;
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

static struct stack_frame *current_frame;

/* The latest block currently used for allocation. current_block->next is
   always NULL. */
static struct stack_block *current_block;
/* The largest block that data stack has allocated so far, which was already
   freed. This can prevent rapid malloc()+free()ing when data stack is grown
   and shrunk constantly. */
static struct stack_block *unused_block = NULL;

static struct event *event_datastack = NULL;
static bool event_datastack_deinitialized = FALSE;

static struct stack_block *last_buffer_block;
static size_t last_buffer_size;
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

		/* We assume that this function gets called before
		   current_block changes. */
		i_assert(last_buffer_block == current_block);

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
		/* NOTE: If the below panic triggers, it may also be due to an
		   internal bug in data-stack (since this is rather complex). While
		   debugging whether that is the case, it's a good idea to change the
		   i_panic() to abort(). Otherwise the i_panic() changes the
		   data-stack's internal state and complicates debugging. */
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
	struct stack_frame *frame;

	i_assert(marker != NULL);

	if (unlikely(!data_stack_initialized)) {
		/* kludgy, but allow this before initialization */
		data_stack_init();
		return t_push(marker);
	}

	/* allocate new block */
	frame = t_buffer_get(sizeof(*frame));
	frame->prev = current_frame;
	current_frame = frame;

	/* mark our current position */
	current_frame->block = current_block;
	current_frame->block_space_left = current_block->left;
	current_frame->last_alloc_size = 0;
	current_frame->marker = marker;
#ifdef DEBUG
	current_frame->alloc_bytes = 0;
	current_frame->alloc_count = 0;
#endif

	t_buffer_alloc(sizeof(*frame));

#ifndef STATIC_CHECKER
	return data_stack_frame_id++;
#else
	struct data_stack_frame *ds_frame = i_new(struct data_stack_frame, 1);
	ds_frame->id = data_stack_frame_id++;
	return ds_frame;
#endif
}

data_stack_frame_t t_push_named(const char *format, ...)
{
	data_stack_frame_t ret = t_push(format);
#ifdef DEBUG
	va_list args;
	va_start(args, format);
	current_frame->marker = p_strdup_vprintf(unsafe_data_stack_pool, format, args);
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

#ifdef DEBUG
		memset(STACK_BLOCK_DATA(block), CLEAR_CHR, block->size);
#endif

		if (block == &outofmem_area.block)
			;
		else if (unused_block == NULL ||
			 block->size > unused_block->size) {
			free(unused_block);
			unused_block = block;
		} else {
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

	block = current_frame->block;
	pos = block->size - current_frame->block_space_left;
	while (block != NULL) {
		block_canary_check(block);
		used_size = block->size - block->left;
		p = STACK_BLOCK_DATA(block);
		while (pos < used_size) {
			size_t requested_size = *(size_t *)(p + pos);
			if (used_size - pos < requested_size)
				i_panic("data stack[%s]: saved alloc size broken",
					current_frame->marker);
			max_pos = pos + ALLOC_SIZE(requested_size);
			pos += MEM_ALIGN(sizeof(size_t)) + requested_size;

			for (; pos < max_pos; pos++) {
				if (p[pos] != CLEAR_CHR)
					i_panic("data stack[%s]: buffer overflow",
						current_frame->marker);
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
	size_t block_space_left;

	if (unlikely(current_frame == NULL))
		i_panic("t_pop() called with empty stack");

	data_stack_last_buffer_reset(FALSE);
#ifdef DEBUG
	t_pop_verify();
#endif

	/* Usually the block doesn't change. If it doesn't, the next pointer
	   must also be NULL. */
	if (current_block != current_frame->block) {
		current_block = current_frame->block;
		if (current_block->next != NULL) {
			/* free unused blocks */
			free_blocks(current_block->next);
			current_block->next = NULL;
		}
	}
	block_canary_check(current_block);

	/* current_frame points inside the stack frame that will be freed.
	   make sure it's not accessed after it's already freed/cleaned. */
	block_space_left = current_frame->block_space_left;
	current_frame = current_frame->prev;

#ifdef DEBUG
	size_t start_pos, end_pos;

	start_pos = current_block->size - block_space_left;
	end_pos = current_block->size - current_block->left_lowwater;
	i_assert(end_pos >= start_pos);
	memset(STACK_BLOCK_DATA(current_block) + start_pos, CLEAR_CHR,
	       end_pos - start_pos);
	current_block->left_lowwater = block_space_left;
#endif

	current_block->left = block_space_left;

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

bool t_pop_pass_str(data_stack_frame_t *id, const char **str)
{
	if (str == NULL || !data_stack_frame_contains(id, *str))
		return t_pop(id);

	/* FIXME: The string could be memmove()d to the beginning of the
	   data stack frame and the previous frame's size extended past it.
	   This would avoid the malloc. It's a bit complicated though. */
	char *tmp_str = i_strdup(*str);
	bool ret = t_pop(id);
	*str = t_strdup(tmp_str);
	i_free(tmp_str);
	return ret;
}

static void mem_block_reset(struct stack_block *block)
{
	block->prev = NULL;
	block->next = NULL;
	block->left = block->size;
#ifdef DEBUG
	block->left_lowwater = block->size;
#endif
}

static struct stack_block *mem_block_alloc(size_t min_size)
{
	struct stack_block *block;
	size_t prev_size, alloc_size;

	prev_size = current_block == NULL ? 0 : current_block->size;
	/* Use INITIAL_STACK_SIZE without growing it to nearest power. */
	alloc_size = prev_size == 0 ? min_size :
		nearest_power(MALLOC_ADD(prev_size, min_size));

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
		i_panic("data stack: Out of memory when allocating %zu bytes",
			alloc_size + SIZEOF_MEMBLOCK);
	}
	block->size = alloc_size;
	block->canary = BLOCK_CANARY;
	mem_block_reset(block);
#ifdef DEBUG
	memset(STACK_BLOCK_DATA(block), CLEAR_CHR, alloc_size);
#endif
	return block;
}

static void data_stack_send_grow_event(size_t last_alloc_size)
{
	if (event_datastack_deinitialized) {
		/* already in the deinitialization code -
		   don't send more events */
		return;
	}
	if (event_datastack == NULL)
		event_datastack = event_create(NULL);
	event_set_name(event_datastack, "data_stack_grow");
	event_add_int(event_datastack, "alloc_size", data_stack_get_alloc_size());
	event_add_int(event_datastack, "used_size", data_stack_get_used_size());
	event_add_int(event_datastack, "last_alloc_size", last_alloc_size);
	event_add_int(event_datastack, "last_block_size", current_block->size);
#ifdef DEBUG
	event_add_int(event_datastack, "frame_alloc_bytes",
		      current_frame->alloc_bytes);
	event_add_int(event_datastack, "frame_alloc_count",
		      current_frame->alloc_count);
#endif
	event_add_str(event_datastack, "frame_marker", current_frame->marker);

	/* It's possible that the data stack gets grown and shrunk rapidly.
	   Try to avoid doing expensive work if the event isn't even used for
	   anything. Note that at this point all the event fields must be
	   set already that might potentially be used by the filters. */
	if (!event_want_debug(event_datastack))
		return;

	/* Getting backtrace is potentially inefficient, so do it after
	   checking if the event is wanted. Note that this prevents using the
	   backtrace field in event field comparisons. */
	const char *backtrace, *error;
	if (backtrace_get(&backtrace, &error) == 0)
		event_add_str(event_datastack, "backtrace", backtrace);
	else
		event_add_str(event_datastack, "backtrace_error", error);

	string_t *str = t_str_new(128);
	str_printfa(str, "total_used=%zu, total_alloc=%zu, last_alloc_size=%zu",
		    data_stack_get_used_size(),
		    data_stack_get_alloc_size(),
		    last_alloc_size);
#ifdef DEBUG
	str_printfa(str, ", frame_bytes=%llu, frame_alloc_count=%u",
		    current_frame->alloc_bytes, current_frame->alloc_count);
#endif
	e_debug(event_datastack, "Growing data stack by %zu for '%s' (%s)",
		current_block->size, current_frame->marker,
		str_c(str));
}

static void *t_malloc_real(size_t size, bool permanent)
{
	void *ret;
	size_t alloc_size;
	bool warn = FALSE;
#ifdef DEBUG
	int old_errno = errno;
#endif

	if (unlikely(size == 0 || size > SSIZE_T_MAX))
		i_panic("Trying to allocate %zu bytes", size);

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
		current_frame->alloc_bytes += alloc_size;
		current_frame->alloc_count++;
	}
#endif
	data_stack_last_buffer_reset(TRUE);

	if (permanent) {
		/* used for t_try_realloc() */
		current_frame->last_alloc_size = alloc_size;
	}

	if (current_block->left < alloc_size) {
		struct stack_block *block;

		/* current block is full, see if we can use the unused_block */
		if (unused_block != NULL && unused_block->size >= alloc_size) {
			block = unused_block;
			unused_block = NULL;
			mem_block_reset(block);
		} else {
			/* current block is full, allocate a new one */
			block = mem_block_alloc(alloc_size);
			warn = TRUE;
		}

		/* The newly allocated block will replace the current_block,
		   i.e. current_block always points to the last element in
		   the linked list. */
		block->prev = current_block;
		current_block->next = block;
		current_block = block;
	}

	/* enough space in current block, use it */
	ret = data_stack_after_last_alloc(current_block);

#ifdef DEBUG
	if (current_block->left - alloc_size < current_block->left_lowwater)
		current_block->left_lowwater = current_block->left - alloc_size;
#endif
	if (permanent)
		current_block->left -= alloc_size;

	if (warn) T_BEGIN {
		/* sending event can cause errno changes. */
#ifdef DEBUG
		i_assert(errno == old_errno);
#else
		int old_errno = errno;
#endif
		/* warn after allocation, so if e_debug() wants to
		   allocate more memory we don't go to infinite loop */
		data_stack_send_grow_event(alloc_size);
		/* reset errno back to what it was */
		errno = old_errno;
	} T_END;
#ifdef DEBUG
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

bool ATTR_NO_SANITIZE_INTEGER
t_try_realloc(void *mem, size_t size)
{
	size_t debug_adjust = 0, last_alloc_size;
	unsigned char *after_last_alloc;

	if (unlikely(size == 0 || size > SSIZE_T_MAX))
		i_panic("Trying to allocate %zu bytes", size);
	block_canary_check(current_block);
	data_stack_last_buffer_reset(TRUE);

	last_alloc_size = current_frame->last_alloc_size;

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
			current_frame->last_alloc_size = new_alloc_size;
#ifdef DEBUG
			if (current_block->left < current_block->left_lowwater)
				current_block->left_lowwater = current_block->left;
			/* All reallocs are permanent by definition
			   However, they don't count as a new allocation */
			current_frame->alloc_bytes += alloc_growth;
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
	block_canary_check(current_block);
#ifndef DEBUG
	const unsigned int min_extra = 0;
#else
	const unsigned int min_extra = SENTRY_COUNT + MEM_ALIGN(sizeof(size_t));
	if (current_block->left < min_extra)
		return 0;
#endif
	size_t size = current_block->left - min_extra;
	i_assert(ALLOC_SIZE(size) == current_block->left);
	return size;
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

bool data_stack_frame_contains(data_stack_frame_t *id, const void *_ptr)
{
	const unsigned char *block_data, *ptr = _ptr;
	const struct stack_block *block;
	unsigned int wanted_frame_id;
	size_t block_start_pos, block_used;

	/* first handle the fast path - NULL can never be within the frame */
	if (ptr == NULL)
		return FALSE;

#ifndef STATIC_CHECKER
	wanted_frame_id = *id;
#else
	wanted_frame_id = (*id)->id;
#endif
	/* Too much effort to support more than the latest frame.
	   It's the only thing that is currently needed anyway. */
	i_assert(wanted_frame_id+1 == data_stack_frame_id);
	block = current_frame->block;
	i_assert(block != NULL);

	/* See if it's in the frame's first block. Only the data after
	   block_start_pos belong to this frame. */
	block_data = STACK_BLOCK_DATA(block);
	block_start_pos = block->size - current_frame->block_space_left;
	block_used = block->size - block->left;
	if (ptr >= block_data + block_start_pos &&
	    ptr <= block_data + block_used)
		return TRUE;

	/* See if it's in the other blocks. All the data in them belong to
	   this frame. */
	for (block = block->next; block != NULL; block = block->next) {
		block_data = STACK_BLOCK_DATA(block);
		block_used = block->size - block->left;
		if (ptr >= block_data && ptr < block_data + block_used)
			return TRUE;
	}
	return FALSE;
}

size_t data_stack_get_alloc_size(void)
{
	struct stack_block *block;
	size_t size = 0;

	i_assert(current_block->next == NULL);

	for (block = current_block; block != NULL; block = block->prev)
		size += block->size;
	return size;
}

size_t data_stack_get_used_size(void)
{
	struct stack_block *block;
	size_t size = 0;

	i_assert(current_block->next == NULL);

	for (block = current_block; block != NULL; block = block->prev)
		size += block->size - block->left;
	return size;
}

void data_stack_free_unused(void)
{
	free(unused_block);
	unused_block = NULL;
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
	current_frame = NULL;

	last_buffer_block = NULL;
	last_buffer_size = 0;

	root_frame_id = t_push("data_stack_init");
}

void data_stack_deinit_event(void)
{
	event_unref(&event_datastack);
	event_datastack_deinitialized = TRUE;
}

void data_stack_deinit(void)
{
	if (!t_pop(&root_frame_id) ||
	    current_frame != NULL)
		i_panic("Missing t_pop() call");

	free(current_block);
	current_block = NULL;
	data_stack_free_unused();
}
