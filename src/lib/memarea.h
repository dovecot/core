#ifndef MEMAREA_H
#define MEMAREA_H

typedef void memarea_free_callback_t(void *context);

/* Create reference counted memory area. The callback is called when the
   refcount drops to 0. */
struct memarea *
memarea_init(const void *data, size_t size,
	     memarea_free_callback_t *callback, void *context);
#define memarea_init(data, size, callback, context) \
	memarea_init(data, size - \
		CALLBACK_TYPECHECK(callback, void (*)(typeof(context))), \
		(memarea_free_callback_t *)callback, context)
/* Returns an empty memory area. */
struct memarea *memarea_init_empty(void);

void memarea_ref(struct memarea *area);
void memarea_unref(struct memarea **area);
/* Free the memory area without calling the callback.
   This is allowed only when refcount==1. */
void memarea_free_without_callback(struct memarea **area);

unsigned int memarea_get_refcount(struct memarea *area);
const void *memarea_get(struct memarea *area, size_t *size_r);
size_t memarea_get_size(struct memarea *area);

/* free-callback that does nothing */
void memarea_free_callback_noop(void *context);

#endif
