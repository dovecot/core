/* Copyright (c) 2007-2018 Dovecot authors, see the included COPYING file */

#include "test-lib.h"

#define SENSE 0xAB /* produces 10101011 */

static bool mem_has_bytes(const void *mem, size_t size, uint8_t b)
{
	const uint8_t *bytes = mem;
	unsigned int i;

	for (i = 0; i < size; i++) {
		if (bytes[i] != b) {
			i_debug("bytes[%u] != %u", i, b);
			return FALSE;
		}
	}
	return TRUE;
}

void test_mempool_allocfree(void)
{
	pool_t pool;
	unsigned int i;
	size_t last_alloc = 0;
	size_t used = 0;
	size_t count = 0;
	void *mem = NULL;

	test_begin("mempool_allocfree");
	pool = pool_allocfree_create("test");

	for(i = 0; i <= 1000; i++) {
		/* release previous allocation */
		if ((i % 3) == 0) {
			if (mem != NULL) {
				test_assert_idx(mem_has_bytes(mem, last_alloc, SENSE), i);
				used -= last_alloc;
				count--;
			}
			last_alloc = 0;
			p_free(pool, mem);
		/* grow previous allocation */
		} else if ((i % 5) == 0) {
			if (mem != NULL)
				used -= last_alloc;
			else
				count++;
			mem = p_realloc(pool, mem, last_alloc, i*2);
			if (last_alloc > 0)
				test_assert_idx(mem_has_bytes(mem, last_alloc, SENSE), i);
			memset(mem, SENSE, i*2);
			last_alloc = i*2;
			used += i*2;
		/* shrink previous allocation */
		} else if ((i % 7) == 0) {
			if (mem != NULL)
				used -= last_alloc;
			else
				count++;
			mem = p_realloc(pool, mem, last_alloc, i-2);
			if (last_alloc > 0)
				test_assert_idx(mem_has_bytes(mem, i-2, SENSE), i);
			memset(mem, SENSE, i-2);
			last_alloc = i-2;
			used += i-2;
		/* allocate some memory */
		} else {
			mem = p_malloc(pool, i);
			/* fill it with sense marker */
			memset(mem, SENSE, i);
			used += i;
			count++;
			last_alloc = i;
		}
	}

	test_assert(pool_allocfree_get_total_used_size(pool) == used);

	pool_unref(&pool);

	/* make sure realloc works correctly */
	pool = pool_allocfree_create("test");
	mem = NULL;

	for(i = 1; i < 1000; i++) {
		mem = p_realloc(pool, mem, i-1, i);
		test_assert_idx(mem_has_bytes(mem, i-1, 0xde), i);
		memset(mem, 0xde, i);
	}

	pool_unref(&pool);

	test_end();
}

enum fatal_test_state fatal_mempool_allocfree(unsigned int stage)
{
	static pool_t pool;

	if (pool == NULL && stage != 0)
		return FATAL_TEST_FAILURE;

	switch(stage) {
	case 0: /* forbidden size */
		test_begin("fatal_mempool_allocfree");
		pool = pool_allocfree_create("fatal");
		test_expect_fatal_string("Trying to allocate 0 bytes");
		(void)p_malloc(pool, 0);
		return FATAL_TEST_FAILURE;

	case 1: /* logically impossible size */
		test_expect_fatal_string("Trying to allocate");
		(void)p_malloc(pool, POOL_MAX_ALLOC_SIZE + 1ULL);
		return FATAL_TEST_FAILURE;

#ifdef _LP64 /* malloc(POOL_MAX_ALLOC_SIZE) may succeed with 32bit */
	case 2: /* physically impossible size */
		test_expect_fatal_string("Out of memory");
		(void)p_malloc(pool, POOL_MAX_ALLOC_SIZE);
		return FATAL_TEST_FAILURE;
#endif

	/* Continue with other tests as follows:
	case 3:
		something_fatal();
		return FATAL_TEST_FAILURE;
	*/
	}

	/* Either our tests have finished, or the test suite has got confused. */
	pool_unref(&pool);
	test_end();
	return FATAL_TEST_FINISHED;
}
