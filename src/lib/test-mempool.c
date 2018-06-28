/* Copyright (c) 2017-2018 Dovecot authors, see the included COPYING file */

#include "test-lib.h"

#if SIZEOF_VOID_P == 8
typedef char uint32max_array_t[4294967295];
#else
typedef char uint32max_array_t[65535];
#endif

#if defined(_LP64)
#define LITTLE_MAX		((unsigned long long) UINT32_MAX)
#define BIG_MAX			((unsigned long long) UINT64_MAX)
#elif defined(_ILP32)
#define LITTLE_MAX		((unsigned long long) UINT16_MAX)
#define BIG_MAX			((unsigned long long) UINT32_MAX)
#else
#error unsupported pointer size
#endif

extern struct pool test_pool;

static void test_mempool_overflow(void)
{
	test_begin("mempool overflow");

	const size_t max_num_u32 = BIG_MAX / sizeof(uint32_t);
	uint32max_array_t *m1 = p_new(&test_pool, uint32max_array_t, LITTLE_MAX + 2);
	test_assert(m1 == POINTER_CAST(BIG_MAX));
	char *m2 = p_new(&test_pool, char, BIG_MAX);
	test_assert(m2 == POINTER_CAST(BIG_MAX));
	uint32_t *m3 = p_new(&test_pool, uint32_t, max_num_u32);
	test_assert(m3 == POINTER_CAST(BIG_MAX - 3));

	/* grow */
	test_assert(p_realloc_type(&test_pool, m1, uint32max_array_t, LITTLE_MAX + 1, LITTLE_MAX + 2) == POINTER_CAST(BIG_MAX));
	test_assert(p_realloc_type(&test_pool, m2, char, BIG_MAX - 1, BIG_MAX) == POINTER_CAST(BIG_MAX));
	test_assert(p_realloc_type(&test_pool, m3, uint32_t, max_num_u32 - 1, max_num_u32) == POINTER_CAST(BIG_MAX - 3));

	/* shrink */
	test_assert(p_realloc_type(&test_pool, m1, uint32max_array_t, LITTLE_MAX + 2, LITTLE_MAX + 1) == POINTER_CAST(BIG_MAX - LITTLE_MAX));
	test_assert(p_realloc_type(&test_pool, m2, char, BIG_MAX, BIG_MAX - 1) == POINTER_CAST(BIG_MAX - 1));
	test_assert(p_realloc_type(&test_pool, m3, uint32_t, max_num_u32, max_num_u32 - 1) == POINTER_CAST(BIG_MAX - 2 * sizeof(uint32_t) + 1));

	test_end();
}

enum fatal_test_state fatal_mempool(unsigned int stage)
{
	static uint32max_array_t *m1;
	static uint32_t *m2;

	test_expect_fatal_string("memory allocation overflow");
	switch(stage) {
	case 0:
		test_begin("fatal mempool overflow");
		m1 = p_new(&test_pool, uint32max_array_t, LITTLE_MAX + 3);
		return FATAL_TEST_FAILURE;
	case 1:
		m2 = p_new(&test_pool, uint32_t, BIG_MAX / sizeof(uint32_t) + 1);
		return FATAL_TEST_FAILURE;
	case 2: /* grow */
		m1 = p_realloc_type(&test_pool, m1, uint32max_array_t,
				    LITTLE_MAX + 2, LITTLE_MAX + 3);
		return FATAL_TEST_FAILURE;
	case 3:
		m2 = p_realloc_type(&test_pool, m2, uint32_t,
				    BIG_MAX / sizeof(uint32_t),
				    BIG_MAX / sizeof(uint32_t) + 1);
		return FATAL_TEST_FAILURE;
	case 4: /* shrink */
		m1 = p_realloc_type(&test_pool, m1, uint32max_array_t,
				    LITTLE_MAX + 3, LITTLE_MAX + 2);
		return FATAL_TEST_FAILURE;
	case 5:
		m2 = p_realloc_type(&test_pool, m2, uint32_t,
				    BIG_MAX / sizeof(uint32_t) + 1,
				    BIG_MAX / sizeof(uint32_t));
		return FATAL_TEST_FAILURE;
	}
	test_expect_fatal_string(NULL);
	test_end();
	return FATAL_TEST_FINISHED;
}

static const char *pool_test_get_name(pool_t pool ATTR_UNUSED) { return "test"; }
static void pool_test_ref(pool_t pool ATTR_UNUSED) { }
static void pool_test_unref(pool_t *pool) { *pool = NULL; }
static void *pool_test_malloc(pool_t pool ATTR_UNUSED, size_t size) { return POINTER_CAST(size); }
static void pool_test_free(pool_t pool ATTR_UNUSED, void *mem ATTR_UNUSED) { }
static void *pool_test_realloc(pool_t pool ATTR_UNUSED, void *mem ATTR_UNUSED,
			       size_t old_size ATTR_UNUSED, size_t new_size) {
	return POINTER_CAST(new_size);
}
static void pool_test_clear(pool_t pool ATTR_UNUSED) { }
static size_t pool_test_get_max_easy_alloc_size(pool_t pool ATTR_UNUSED) { return 12345; }
static const struct pool_vfuncs test_pool_vfuncs = {
	pool_test_get_name,
	pool_test_ref,
	pool_test_unref,
	pool_test_malloc,
	pool_test_free,
	pool_test_realloc,
	pool_test_clear,
	pool_test_get_max_easy_alloc_size
};

struct pool test_pool = {
	.v = &test_pool_vfuncs,

	.alloconly_pool = TRUE,
	.datastack_pool = FALSE,
};

void test_mempool(void)
{
	test_mempool_overflow();
}
