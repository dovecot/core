/* Copyright (c) 2003-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "aqueue.h"

struct aqueue *aqueue_init(struct array *array)
{
	struct aqueue *aqueue;

	aqueue = i_new(struct aqueue, 1);
	aqueue->arr = array;
	aqueue->area_size = buffer_get_size(aqueue->arr->buffer) /
		aqueue->arr->element_size;
	i_assert(aqueue->area_size > 0);
	return aqueue;
}

void aqueue_deinit(struct aqueue **_aqueue)
{
	struct aqueue *aqueue = *_aqueue;

	*_aqueue = NULL;
	i_free(aqueue);
}

static void aqueue_grow(struct aqueue *aqueue)
{
	unsigned int orig_area_size, count;

	i_assert(aqueue->full && aqueue->head == aqueue->tail);

	orig_area_size = aqueue->area_size;
	(void)array_append_space_i(aqueue->arr);
	aqueue->area_size = buffer_get_size(aqueue->arr->buffer) /
		aqueue->arr->element_size;
	i_assert(orig_area_size < aqueue->area_size);

	count = I_MIN(aqueue->area_size - orig_area_size, aqueue->head);
	array_copy(aqueue->arr, orig_area_size, aqueue->arr, 0, count);
	if (count < aqueue->area_size - orig_area_size)
		aqueue->head = orig_area_size + count;
	else {
		array_copy(aqueue->arr, 0, aqueue->arr, count,
			   aqueue->head - count);
		aqueue->head -= count;
	}

	i_assert(aqueue->head != aqueue->tail);
	aqueue->full = FALSE;
}

void aqueue_append(struct aqueue *aqueue, const void *data)
{
	if (aqueue->full) {
		aqueue_grow(aqueue);
		i_assert(!aqueue->full);
	}

	array_idx_set_i(aqueue->arr, aqueue->head, data);
	aqueue->head = (aqueue->head + 1) % aqueue->area_size;
	aqueue->full = aqueue->head == aqueue->tail;
}

void aqueue_delete(struct aqueue *aqueue, unsigned int n)
{
	unsigned int idx, count = aqueue_count(aqueue);

	i_assert(n < count);

	aqueue->full = FALSE;
	if (n == 0) {
		/* optimized deletion from tail */
		aqueue->tail = (aqueue->tail + 1) % aqueue->area_size;
		return;
	}
	if (n == count-1) {
		/* optimized deletion from head */
		aqueue->head = (aqueue->head + aqueue->area_size - 1) %
			aqueue->area_size;
		return;
	}

	idx = aqueue_idx(aqueue, n);
	if ((n < count/2 || idx > aqueue->head) && idx > aqueue->tail) {
		/* move tail forward.
		   ..tail##idx##head.. or ##head..tail##idx## */
		array_copy(aqueue->arr, aqueue->tail + 1,
			   aqueue->arr, aqueue->tail,
			   idx - aqueue->tail);
		aqueue->tail++;
		i_assert(aqueue->tail < aqueue->area_size);
	} else {
		/* move head backward.
		   ..tail##idx##head.. or ##idx##head..tail## */
		i_assert(idx < aqueue->head);
		array_copy(aqueue->arr, idx,
			   aqueue->arr, idx + 1,
			   aqueue->head - idx);
		aqueue->head = (aqueue->head + aqueue->area_size - 1) %
			aqueue->area_size;
	}
	i_assert(aqueue->head < aqueue->area_size &&
		 aqueue->head != aqueue->tail);
}

void aqueue_delete_tail(struct aqueue *aqueue)
{
	aqueue_delete(aqueue, 0);
}

void aqueue_clear(struct aqueue *aqueue)
{
	aqueue->head = aqueue->tail = 0;
	aqueue->full = FALSE;
}

unsigned int aqueue_count(const struct aqueue *aqueue)
{
	unsigned int area_size = aqueue->area_size;

	return aqueue->full ? area_size :
		(area_size - aqueue->tail + aqueue->head) % area_size;
}
