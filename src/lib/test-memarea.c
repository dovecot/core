/* Copyright (c) 2017-2018 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "buffer.h"
#include "memarea.h"

static bool test_callback_called = FALSE;

static void test_callback(buffer_t *buf)
{
	test_assert(!test_callback_called);
	test_callback_called = TRUE;
	buffer_free(&buf);
}

void test_memarea(void)
{
	struct memarea *area, *area2;
	buffer_t *buf;
	size_t size;

	test_begin("memarea");
	buf = buffer_create_dynamic(default_pool, 128);
	buffer_append(buf, "123", 3);

	area = memarea_init(buf->data, buf->used, test_callback, buf);
	test_assert(memarea_get_refcount(area) == 1);
	test_assert(memarea_get(area, &size) == buf->data && size == buf->used);

	area2 = area;
	memarea_ref(area2);
	test_assert(memarea_get_refcount(area2) == 2);
	test_assert(memarea_get(area2, &size) == buf->data && size == buf->used);
	memarea_unref(&area2);
	test_assert(area2 == NULL);
	test_assert(!test_callback_called);

	memarea_unref(&area);
	test_assert(test_callback_called);

	test_end();
}
