#ifndef AQUEUE_H
#define AQUEUE_H

/* Dynamically growing queue. Use the array directly to access the data,
   for example:

   count = queue_count(queue);
   for (i = 0; i < count; i++) {
     data = array[queue_idx(i)];
   }
*/

struct aqueue {
	struct array *arr;
	unsigned int head, tail, area_size;
	bool full;
};

struct aqueue *aqueue_init(struct array *array);
void aqueue_deinit(struct aqueue **aqueue);

/* Append item to head */
void aqueue_append(struct aqueue *aqueue, const void *data);
/* Delete last item from tail */
void aqueue_delete_tail(struct aqueue *aqueue);
/* Remove item from n'th position */
void aqueue_delete(struct aqueue *aqueue, unsigned int n);
/* Clear the entire aqueue */
void aqueue_clear(struct aqueue *aqueue);

/* Returns the number of items in aqueue. */
unsigned int aqueue_count(const struct aqueue *aqueue) ATTR_PURE;

/* Returns array index of n'th element in aqueue. */
static inline unsigned int ATTR_PURE
aqueue_idx(const struct aqueue *aqueue, unsigned int n)
{
	return (aqueue->tail + n) % aqueue->area_size;
}

#endif
