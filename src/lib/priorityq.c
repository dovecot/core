/* Copyright (c) 2008-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "priorityq.h"

/* Macros for moving inside an array implementation of binary tree where
   [0] is the root. */
#define PARENT_IDX(idx) \
	(((idx) - 1) / 2)
#define LEFT_CHILD_IDX(idx) \
	((idx) * 2 + 1)
#define RIGHT_CHILD_IDX(idx) \
	((idx) * 2 + 2)

struct priorityq {
	priorityq_cmp_callback_t *cmp_callback;

	ARRAY(struct priorityq_item *) items;
};

struct priorityq *
priorityq_init(priorityq_cmp_callback_t *cmp_callback, unsigned int init_size)
{
	struct priorityq *pq;

	pq = i_new(struct priorityq, 1);
	pq->cmp_callback = cmp_callback;
	i_array_init(&pq->items, init_size);
	return pq;
}

void priorityq_deinit(struct priorityq **_pq)
{
	struct priorityq *pq = *_pq;

	*_pq = NULL;
	array_free(&pq->items);
	i_free(pq);
}

unsigned int priorityq_count(const struct priorityq *pq)
{
	return array_count(&pq->items);
}

static void heap_items_swap(struct priorityq_item **items,
			    unsigned int idx1, unsigned int idx2)
{
	struct priorityq_item *tmp;

	/* swap the item indexes */
	i_assert(items[idx1]->idx == idx1);
	i_assert(items[idx2]->idx == idx2);

	items[idx1]->idx = idx2;
	items[idx2]->idx = idx1;

	/* swap the item pointers */
	tmp = items[idx1];
	items[idx1] = items[idx2];
	items[idx2] = tmp;
}

static unsigned int
heap_item_bubble_up(struct priorityq *pq, unsigned int idx)
{
	struct priorityq_item **items;
	unsigned int parent_idx, count;

	items = array_get_modifiable(&pq->items, &count);
	while (idx > 0) {
		parent_idx = PARENT_IDX(idx);

		i_assert(idx < count);
		if (pq->cmp_callback(items[idx], items[parent_idx]) >= 0)
			break;

		/* wrong order - swap */
		heap_items_swap(items, idx, parent_idx);
		idx = parent_idx;
	}
	return idx;
}

static void heap_item_bubble_down(struct priorityq *pq, unsigned int idx)
{
	struct priorityq_item **items;
	unsigned int left_idx, right_idx, min_child_idx, count;

	items = array_get_modifiable(&pq->items, &count);
	while ((left_idx = LEFT_CHILD_IDX(idx)) < count) {
		right_idx = RIGHT_CHILD_IDX(idx);
		if (right_idx >= count ||
		    pq->cmp_callback(items[left_idx], items[right_idx]) < 0)
			min_child_idx = left_idx;
		else
			min_child_idx = right_idx;

		if (pq->cmp_callback(items[min_child_idx], items[idx]) >= 0)
			break;

		/* wrong order - swap */
		heap_items_swap(items, idx, min_child_idx);
		idx = min_child_idx;
	}
}

void priorityq_add(struct priorityq *pq, struct priorityq_item *item)
{
	item->idx = array_count(&pq->items);
	array_push_back(&pq->items, &item);
	(void)heap_item_bubble_up(pq, item->idx);
}

static void priorityq_remove_idx(struct priorityq *pq, unsigned int idx)
{
	struct priorityq_item **items;
	unsigned int count;

	items = array_get_modifiable(&pq->items, &count);
	i_assert(idx < count);

	/* move last item over the removed one and fix the heap */
	count--;
	heap_items_swap(items, idx, count);
	array_delete(&pq->items, count, 1);

	if (count > 0 && idx != count) {
		if (idx > 0)
			idx = heap_item_bubble_up(pq, idx);
		heap_item_bubble_down(pq, idx);
	}
}

void priorityq_remove(struct priorityq *pq, struct priorityq_item *item)
{
	priorityq_remove_idx(pq, item->idx);
	item->idx = UINT_MAX;
}

struct priorityq_item *priorityq_peek(struct priorityq *pq)
{
	struct priorityq_item *const *items;

	if (array_count(&pq->items) == 0)
		return NULL;

	items = array_first(&pq->items);
	return items[0];
}

struct priorityq_item *priorityq_pop(struct priorityq *pq)
{
	struct priorityq_item *item;

	item = priorityq_peek(pq);
	if (item != NULL) {
		priorityq_remove_idx(pq, 0);
		item->idx = UINT_MAX;
	}
	return item;
}

struct priorityq_item *const *priorityq_items(struct priorityq *pq)
{
	if (array_count(&pq->items) == 0)
		return NULL;

	return array_first(&pq->items);
}
