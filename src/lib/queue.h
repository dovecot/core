#ifndef QUEUE_H
#define QUEUE_H

/* Dynamically growing queue. Use the array directly to access the data,
   for example:

   count = queue_count(queue);
   for (i = 0; i < count; i++) {
     data = array[queue_idx(i)];
   }
*/

struct queue {
	struct array *arr;
	unsigned int head, tail, area_size;
	bool full;
};

struct queue *queue_init(struct array *array);
void queue_deinit(struct queue **queue);

/* Append item to head */
void queue_append(struct queue *queue, const void *data);
/* Delete last item from tail */
void queue_delete_tail(struct queue *queue);
/* Remove item from n'th position */
void queue_delete(struct queue *queue, unsigned int n);
/* Clear the entire queue */
void queue_clear(struct queue *queue);

/* Returns the number of items in queue. */
unsigned int queue_count(const struct queue *queue);

/* Returns array index of n'th element in queue. */
static inline unsigned int queue_idx(const struct queue *queue, unsigned int n)
{
	return (queue->tail + n) % queue->area_size;
}

#endif
