/* Copyright (c) 2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "memarea.h"

struct memarea {
	const void *data;
	size_t size;

	memarea_free_callback_t *callback;
	void *context;

	int refcount;
};

static struct memarea memarea_empty = {
	.refcount = 1,
};

#undef memarea_init
struct memarea *
memarea_init(const void *data, size_t size,
	     memarea_free_callback_t *callback, void *context)
{
	struct memarea *area;

	i_assert(callback != NULL);

	area = i_new(struct memarea, 1);
	area->data = data;
	area->size = size;
	area->callback = callback;
	area->context = context;
	area->refcount = 1;
	return area;
}

struct memarea *memarea_init_empty(void)
{
	i_assert(memarea_empty.refcount > 0);
	memarea_empty.refcount++;
	return &memarea_empty;
}

void memarea_ref(struct memarea *area)
{
	i_assert(area->refcount > 0);
	area->refcount++;
}

void memarea_unref(struct memarea **_area)
{
	struct memarea *area = *_area;

	*_area = NULL;
	i_assert(area->refcount > 0);

	if (--area->refcount > 0)
		return;
	i_assert(area != &memarea_empty);
	area->callback(area->context);
	i_free(area);
}

void memarea_free_without_callback(struct memarea **_area)
{
	struct memarea *area = *_area;

	*_area = NULL;
	i_assert(memarea_get_refcount(area) == 1);
	i_free(area);
}

unsigned int memarea_get_refcount(struct memarea *area)
{
	i_assert(area->refcount > 0);
	return area->refcount;
}

const void *memarea_get(struct memarea *area, size_t *size_r)
{
	*size_r = area->size;
	return area->data;
}

size_t memarea_get_size(struct memarea *area)
{
	return area->size;
}

void memarea_free_callback_noop(void *context ATTR_UNUSED)
{
}
