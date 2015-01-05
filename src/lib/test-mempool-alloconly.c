/* Copyright (c) 2007-2015 Dovecot authors, see the included COPYING file */

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
#define PMALLOC_MAX_COUNT 128
	pool_t pool;
	unsigned int i, j, k;
	void *mem[PMALLOC_MAX_COUNT + 1];
	bool success = TRUE;

	for (i = 0; i < 64; i++) {
		for (j = 1; j <= 128; j++) {
			pool = pool_alloconly_create(MEMPOOL_GROWING"test", i);
			mem[0] = p_malloc(pool, j);
			memset(mem[0], j, j);

			for (k = 1; k <= PMALLOC_MAX_COUNT; k++) {
				mem[k] = p_malloc(pool, k);
				memset(mem[k], k, k);
			}

			if (!mem_has_bytes(mem[0], j, j))
				success = FALSE;
			for (k = 1; k <= PMALLOC_MAX_COUNT; k++) {
				if (!mem_has_bytes(mem[k], k, k))
					success = FALSE;
			}
			pool_unref(&pool);
		}
	}
	test_out("mempool_alloconly", success);
}

enum fatal_test_state fatal_mempool(int stage)
{
	static pool_t pool;

	switch(stage) {
	case 0: /* forbidden size */
		test_begin("fatal_mempool");
		pool = pool_alloconly_create(MEMPOOL_GROWING"fatal", 1);
		(void)p_malloc(pool, 0);
		return FATAL_TEST_FAILURE;

	case 1: /* logically impossible size */
		(void)p_malloc(pool, SSIZE_T_MAX + 1ULL);
		return FATAL_TEST_FAILURE;

	case 2: /* physically impossible size */
		(void)p_malloc(pool, SSIZE_T_MAX - (size_t)MEM_ALIGN(1));
		return FATAL_TEST_FAILURE;

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
