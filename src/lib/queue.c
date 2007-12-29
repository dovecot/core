/* Copyright (c) 2003-2007 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "queue.h"

struct queue *queue_init(struct array *array)
{
	struct queue *queue;

	queue = i_new(struct queue, 1);
	queue->arr = array;
	queue->area_size =
		buffer_get_size(queue->arr->buffer) / queue->arr->element_size;
	i_assert(queue->area_size > 0);
	return queue;
}

void queue_deinit(struct queue **_queue)
{
	struct queue *queue = *_queue;

	*_queue = NULL;
	i_free(queue);
}

static void queue_grow(struct queue *queue)
{
	unsigned int orig_area_size, count;

	i_assert(queue->full && queue->head == queue->tail);

	orig_area_size = queue->area_size;
	(void)array_append_space_i(queue->arr);
	queue->area_size =
		buffer_get_size(queue->arr->buffer) / queue->arr->element_size;
	i_assert(orig_area_size < queue->area_size);

	count = I_MIN(queue->area_size - orig_area_size, queue->head);
	array_copy(queue->arr, orig_area_size, queue->arr, 0, count);
	if (count < queue->area_size - orig_area_size)
		queue->head = orig_area_size + count;
	else {
		array_copy(queue->arr, 0, queue->arr, count,
			   queue->head - count);
		queue->head -= count;
	}

	i_assert(queue->head != queue->tail);
	queue->full = FALSE;
}

void queue_append(struct queue *queue, const void *data)
{
	if (queue->full) {
		queue_grow(queue);
		i_assert(!queue->full);
	}

	array_idx_set_i(queue->arr, queue->head, data);
	queue->head = (queue->head + 1) % queue->area_size;
	queue->full = queue->head == queue->tail;
}

void queue_delete(struct queue *queue, unsigned int n)
{
	unsigned int idx, count = queue_count(queue);

	i_assert(n < count);

	queue->full = FALSE;
	if (n == 0) {
		/* optimized deletion from tail */
		queue->tail = (queue->tail + 1) % queue->area_size;
		return;
	}
	if (n == count-1) {
		/* optimized deletion from head */
		queue->head = (queue->head + queue->area_size - 1) %
			queue->area_size;
		return;
	}

	idx = queue_idx(queue, n);
	if ((n < count/2 || idx > queue->head) && idx > queue->tail) {
		/* move tail forward.
		   ..tail##idx##head.. or ##head..tail##idx## */
		array_copy(queue->arr, queue->tail + 1,
			   queue->arr, queue->tail,
			   idx - queue->tail);
		queue->tail++;
		i_assert(queue->tail < queue->area_size);
	} else {
		/* move head backward.
		   ..tail##idx##head.. or ##idx##head..tail## */
		i_assert(idx < queue->head);
		array_copy(queue->arr, idx,
			   queue->arr, idx + 1,
			   queue->head - idx);
		queue->head = (queue->head + queue->area_size - 1) %
			queue->area_size;
	}
	i_assert(queue->head < queue->area_size && queue->head != queue->tail);
}

void queue_delete_tail(struct queue *queue)
{
	queue_delete(queue, 0);
}

void queue_clear(struct queue *queue)
{
	queue->head = queue->tail = 0;
	queue->full = FALSE;
}

unsigned int queue_count(const struct queue *queue)
{
	unsigned int area_size = queue->area_size;

	return queue->full ? area_size :
		(area_size - queue->tail + queue->head) % area_size;
}
