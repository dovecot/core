/* Copyright (c) 2017-2018 Dovecot authors, see the included COPYING file */

#include "test-lib.h"

#if SIZEOF_VOID_P == 8
typedef char uint32max_array_t[4294967295];
#else
typedef char uint32max_array_t[65535];
#endif

extern struct pool test_pool;

static void test_mempool_overflow(void)
{
	test_begin("mempool overflow");
#if SIZEOF_VOID_P == 8
	uint32max_array_t *m1 = p_new(&test_pool, uint32max_array_t, 4294967297ULL);
	test_assert(m1 == POINTER_CAST(18446744073709551615ULL));
	char *m2 = p_new(&test_pool, char, 18446744073709551615ULL);
	test_assert(m2 == POINTER_CAST(18446744073709551615ULL));
	uint32_t *m3 = p_new(&test_pool, uint32_t, 4611686018427387903ULL);
	test_assert(m3 == POINTER_CAST(18446744073709551612ULL));

	/* grow */
	test_assert(p_realloc_type(&test_pool, m1, uint32max_array_t, 4294967296ULL, 4294967297ULL) == POINTER_CAST(18446744073709551615ULL));
	test_assert(p_realloc_type(&test_pool, m2, char, 18446744073709551614ULL, 18446744073709551615ULL) == POINTER_CAST(18446744073709551615ULL));
	test_assert(p_realloc_type(&test_pool, m3, uint32_t, 4611686018427387902ULL, 4611686018427387903ULL) == POINTER_CAST(18446744073709551612ULL));

	/* shrink */
	test_assert(p_realloc_type(&test_pool, m1, uint32max_array_t, 4294967297ULL, 4294967296ULL) == POINTER_CAST(18446744069414584320ULL));
	test_assert(p_realloc_type(&test_pool, m2, char, 18446744073709551615ULL, 18446744073709551614ULL) == POINTER_CAST(18446744073709551614ULL));
	test_assert(p_realloc_type(&test_pool, m3, uint32_t, 4611686018427387903ULL, 4611686018427387902ULL) == POINTER_CAST(18446744073709551608ULL));
#elif SIZEOF_VOID_P == 4
	uint32max_array_t *m1 = p_new(&test_pool, uint32max_array_t, 65537);
	test_assert(m1 == POINTER_CAST(4294967295U));
	char *m2 = p_new(&test_pool, char, 4294967295U);
	test_assert(m2 == POINTER_CAST(4294967295U));
	uint32_t *m3 = p_new(&test_pool, uint32_t, 1073741823U);
	test_assert(m3 == POINTER_CAST(4294967292U));

	/* grow */
	test_assert(p_realloc_type(&test_pool, m1, uint32max_array_t, 65536, 65537) == POINTER_CAST(4294967295U));
	test_assert(p_realloc_type(&test_pool, m2, char, 4294967294U, 4294967295U) == POINTER_CAST(4294967295U));
	test_assert(p_realloc_type(&test_pool, m3, uint32_t, 1073741822U, 1073741823U) == POINTER_CAST(4294967292U));

	/* shrink */
	test_assert(p_realloc_type(&test_pool, m1, uint32max_array_t, 65537, 65536) == POINTER_CAST(4294901760U));
	test_assert(p_realloc_type(&test_pool, m2, char, 4294967295U, 4294967294U) == POINTER_CAST(4294967294U));
	test_assert(p_realloc_type(&test_pool, m3, uint32_t, 1073741823U, 1073741822U) == POINTER_CAST(4294967288U));
#else
#  error unsupported pointer size
#endif
	test_end();
}

enum fatal_test_state fatal_mempool(unsigned int stage)
{
	static uint32max_array_t *m1;
	static uint32_t *m2;

	test_expect_fatal_string("memory allocation overflow");
#if SIZEOF_VOID_P == 8
	switch(stage) {
	case 0:
		test_begin("fatal mempool overflow");
		m1 = p_new(&test_pool, uint32max_array_t, 4294967298ULL);
		return FATAL_TEST_FAILURE;
	case 1:
		m2 = p_new(&test_pool, uint32_t, 4611686018427387904ULL);
		return FATAL_TEST_FAILURE;
	case 2: /* grow */
		m1 = p_realloc_type(&test_pool, m1, uint32max_array_t, 4294967297ULL, 4294967298ULL);
		return FATAL_TEST_FAILURE;
	case 3:
		m2 = p_realloc_type(&test_pool, m2, uint32_t, 4611686018427387903ULL, 4611686018427387904ULL);
		return FATAL_TEST_FAILURE;
	case 4: /* shrink */
		m1 = p_realloc_type(&test_pool, m1, uint32max_array_t, 4294967298ULL, 4294967297ULL);
		return FATAL_TEST_FAILURE;
	case 5:
		m2 = p_realloc_type(&test_pool, m2, uint32_t, 4611686018427387904ULL, 4611686018427387903ULL);
		return FATAL_TEST_FAILURE;
	}
#elif SIZEOF_VOID_P == 4
	switch(stage) {
	case 0:
		test_begin("fatal mempool overflow");
		m1 = p_new(&test_pool, uint32max_array_t, 65538);
		return FATAL_TEST_FAILURE;
	case 1:
		m2 = p_new(&test_pool, uint32_t, 1073741824U);
		return FATAL_TEST_FAILURE;
	case 2: /* grow */
		m1 = p_realloc_type(&test_pool, m1, uint32max_array_t, 65537, 65538);
		return FATAL_TEST_FAILURE;
	case 3:
		m2 = p_realloc_type(&test_pool, m2, uint32_t, 1073741823U, 1073741824U);
		return FATAL_TEST_FAILURE;
	case 4: /* shrink */
		m1 = p_realloc_type(&test_pool, m1, uint32max_array_t, 65538, 65537);
		return FATAL_TEST_FAILURE;
	case 5:
		m2 = p_realloc_type(&test_pool, m2, uint32_t, 1073741824U, 1073741823U);
		return FATAL_TEST_FAILURE;
	}
#else
#  error unsupported pointer size
#endif
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
