#ifndef PRIORITYQ_H
#define PRIORITYQ_H

/* Priority queue implementation using heap. The items you add to the queue
   must begin with a struct priorityq_item. This is necessary for
   priorityq_remove() to work fast. */

struct priorityq_item {
	/* Current index in the queue array, updated automatically. */
	unsigned int idx;
	/* [your own data] */
};

/* Returns <0, 0 or >0 */
typedef int priorityq_cmp_callback_t(const void *p1, const void *p2);

/* Create a new priority queue. Callback is used to compare added items. */
struct priorityq *
priorityq_init(priorityq_cmp_callback_t *cmp_callback, unsigned int init_size);
void priorityq_deinit(struct priorityq **pq);

/* Return number of items in the queue. */
unsigned int priorityq_count(const struct priorityq *pq) ATTR_PURE;

/* Add a new item to the queue. */
void priorityq_add(struct priorityq *pq, struct priorityq_item *item);
/* Remove the specified item from the queue. */
void priorityq_remove(struct priorityq *pq, struct priorityq_item *item);

/* Return the item with the highest priority. Returns NULL if queue is empty. */
struct priorityq_item *priorityq_peek(struct priorityq *pq);
/* Like priorityq_peek(), but also remove the returned item from the queue. */
struct priorityq_item *priorityq_pop(struct priorityq *pq);
/* Returns array containing all the priorityq_items. Only the first item is
   guaranteed to be the highest priority item, the rest can't be assumed to
   be in any order. */
struct priorityq_item *const *priorityq_items(struct priorityq *pq);

#endif
