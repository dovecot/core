/* Copyright (c) 2017-2018 Dovecot authors, see the included COPYING file */

#include "test-lib.h"

#if SIZEOF_VOID_P == 8
typedef char uint32max_array_t[4294967295];
#else
typedef char uint32max_array_t[65535];
#endif

#define BIG_MAX			POOL_MAX_ALLOC_SIZE

#if defined(_LP64)
#define LITTLE_MAX		((unsigned long long) INT32_MAX)
#elif defined(_ILP32)
#define LITTLE_MAX		((unsigned long long) INT16_MAX)
#else
#error unsupported pointer size
#endif

extern struct pool test_pool;

/* Checks allocations & reallocations for a given type. */
#define CHECK_OVERFLOW(type, nelem, _maxsize)					\
	do {									\
		const size_t maxsize = (_maxsize);				\
		test_begin("mempool overflow - " #type);			\
		type *ptr = p_new(&test_pool, type, (nelem));			\
		test_assert(ptr == POINTER_CAST(maxsize));			\
		/* grow: */							\
		test_assert(p_realloc_type(&test_pool, ptr, type, (nelem) - 1, (nelem)) == POINTER_CAST(maxsize)); \
		/* shrink: */							\
		test_assert(p_realloc_type(&test_pool, ptr, type, (nelem), (nelem) - 1) == POINTER_CAST(maxsize - sizeof(type))); \
		test_end();							\
	} while (0)

static void test_mempool_overflow(void)
{
	CHECK_OVERFLOW(uint32max_array_t, LITTLE_MAX, sizeof(uint32max_array_t) * LITTLE_MAX);
	CHECK_OVERFLOW(char, BIG_MAX, BIG_MAX);
	CHECK_OVERFLOW(uint32_t, BIG_MAX / sizeof(uint32_t), BIG_MAX - 3);
}

enum fatal_test_state fatal_mempool(unsigned int stage)
{
	static uint32max_array_t *m1;
	static uint32_t *m2;

	switch(stage) {
	case 0:
		test_expect_fatal_string("Trying to allocate");
		test_begin("fatal mempool overflow");
		m1 = p_new(&test_pool, uint32max_array_t, LITTLE_MAX + 3);
		return FATAL_TEST_FAILURE;
	case 1:
		test_expect_fatal_string("Trying to allocate");
		m2 = p_new(&test_pool, uint32_t, BIG_MAX / sizeof(uint32_t) + 1);
		return FATAL_TEST_FAILURE;
	case 2: /* grow */
		test_expect_fatal_string("Trying to allocate");
		m1 = p_realloc_type(&test_pool, m1, uint32max_array_t,
				    LITTLE_MAX + 2, LITTLE_MAX + 3);
		return FATAL_TEST_FAILURE;
	case 3:
		test_expect_fatal_string("Trying to allocate");
		m2 = p_realloc_type(&test_pool, m2, uint32_t,
				    BIG_MAX / sizeof(uint32_t),
				    BIG_MAX / sizeof(uint32_t) + 1);
		return FATAL_TEST_FAILURE;
	case 4: /* shrink */
		test_expect_fatal_string("Trying to allocate");
		m1 = p_realloc_type(&test_pool, m1, uint32max_array_t,
				    LITTLE_MAX + 3, LITTLE_MAX + 2);
		return FATAL_TEST_FAILURE;
	case 5:
		test_expect_fatal_string("Trying to allocate");
		m2 = p_realloc_type(&test_pool, m2, uint32_t,
				    BIG_MAX / sizeof(uint32_t) + 2,
				    BIG_MAX / sizeof(uint32_t) + 1);
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
