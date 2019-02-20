/* Copyright (c) 2007-2018 Dovecot authors, see the included COPYING file */

#include "test-lib.h"

static bool mem_has_bytes(const void *mem, size_t size, uint8_t b)
{
	const uint8_t *bytes = mem;
	unsigned int i;

	for (i = 0; i < size; i++) {
		if (bytes[i] != b)
			return FALSE;
	}
	return TRUE;
}

void test_mempool_alloconly(void)
{
#define SENTRY_SIZE 32
#define SENTRY_CHAR 0xDE
#define PMALLOC_MAX_COUNT 128
	pool_t pool;
	unsigned int i, j, k;
	void *mem[PMALLOC_MAX_COUNT + 1];
	char *sentry;

	test_begin("mempool_alloconly");
	for (i = 0; i < 64; i++) {
		for (j = 1; j <= 128; j++) {
			pool = pool_alloconly_create(MEMPOOL_GROWING"test", i);
			/* make sure p_malloc() doesn't overwrite unallocated
			   data in data stack. parts of the code relies on
			   this. */
			sentry = t_buffer_get(SENTRY_SIZE);
			memset(sentry, SENTRY_CHAR, SENTRY_SIZE);

			mem[0] = p_malloc(pool, j);
			memset(mem[0], j, j);

			for (k = 1; k <= PMALLOC_MAX_COUNT; k++) {
				mem[k] = p_malloc(pool, k);
				memset(mem[k], k, k);
			}
			test_assert(mem_has_bytes(sentry, SENTRY_SIZE, SENTRY_CHAR));
			test_assert(t_buffer_get(SENTRY_SIZE) == sentry);

			test_assert(mem_has_bytes(mem[0], j, j));
			for (k = 1; k <= PMALLOC_MAX_COUNT; k++)
				test_assert(mem_has_bytes(mem[k], k, k));
			pool_unref(&pool);
		}
	}
	test_end();
}

enum fatal_test_state fatal_mempool_alloconly(unsigned int stage)
{
	static pool_t pool;

	if (pool == NULL && stage != 0)
		return FATAL_TEST_FAILURE;

	switch(stage) {
	case 0: /* forbidden size */
		test_begin("fatal_mempool_alloconly");
		pool = pool_alloconly_create(MEMPOOL_GROWING"fatal", 1);
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
