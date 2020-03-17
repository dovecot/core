/* Copyright (c) 2016-2018 Dovecot authors, see the included COPYING file */

#include "test-lib.h"

static void test_malloc_overflow_multiply(void)
{
	static const struct {
		size_t a, b;
	} tests[] = {
		{ 0, SIZE_MAX },
		{ 1, SIZE_MAX },
		{ SIZE_MAX/2, 2 },
	};
	test_begin("MALLOC_MULTIPLY()");
	for (unsigned int i = 0; i < N_ELEMENTS(tests); i++) {
		test_assert_idx(MALLOC_MULTIPLY(tests[i].a, tests[i].b) == tests[i].a * tests[i].b, i);
		test_assert_idx(MALLOC_MULTIPLY(tests[i].b, tests[i].a) == tests[i].b * tests[i].a, i);
	}
	test_end();
}

static void test_malloc_overflow_add(void)
{
	static const struct {
		size_t a, b;
	} tests[] = {
		{ 0, SIZE_MAX },
		{ 1, SIZE_MAX-1 },
		{ SIZE_MAX/2+1, SIZE_MAX/2 },
	};
	unsigned short n = 2;

	test_begin("MALLOC_ADD()");
	/* check that no compiler warning is given */
	test_assert(MALLOC_ADD(2, n) == 2U+n);
	for (unsigned int i = 0; i < N_ELEMENTS(tests); i++) {
		test_assert_idx(MALLOC_ADD(tests[i].a, tests[i].b) == tests[i].a + tests[i].b, i);
		test_assert_idx(MALLOC_ADD(tests[i].b, tests[i].a) == tests[i].b + tests[i].a, i);
	}
	test_end();
}

void test_malloc_overflow(void)
{
	test_malloc_overflow_multiply();
	test_malloc_overflow_add();
}

static enum fatal_test_state fatal_malloc_overflow_multiply(unsigned int *stage)
{
	const struct {
		size_t a, b;
	} mul_tests[] = {
		{ SIZE_MAX/2+1, 2 },
	};
	unsigned int i;

	test_expect_fatal_string("memory allocation overflow");
	switch (*stage) {
	case 0:
		test_begin("MALLOC_MULTIPLY() overflows");
		i_error("%zu", MALLOC_MULTIPLY((size_t)SIZE_MAX/2, (uint8_t)3));
		break;
	case 1:
		i_error("%zu", MALLOC_MULTIPLY((uint8_t)3, (size_t)SIZE_MAX/2));
		break;
	}
	*stage -= 2;

	if (*stage >= N_ELEMENTS(mul_tests)*2) {
		*stage -= N_ELEMENTS(mul_tests)*2;
		if (*stage == 0)
			test_end();
		test_expect_fatal_string(NULL);
		return FATAL_TEST_FINISHED;
	}
	i = *stage / 2;

	if (*stage % 2 == 0)
		i_error("%zu", MALLOC_MULTIPLY(mul_tests[i].a, mul_tests[i].b));
	else
		i_error("%zu", MALLOC_MULTIPLY(mul_tests[i].b, mul_tests[i].a));
	return FATAL_TEST_FAILURE;
}

static enum fatal_test_state fatal_malloc_overflow_add(unsigned int *stage)
{
	const struct {
		size_t a, b;
	} add_tests[] = {
		{ SIZE_MAX, 1 },
		{ SIZE_MAX/2+1, SIZE_MAX/2+1 },
	};
	unsigned int i;

	test_expect_fatal_string("memory allocation overflow");
	switch (*stage) {
	case 0:
		test_begin("MALLOC_ADD() overflows");
		i_error("%zu", MALLOC_ADD((size_t)SIZE_MAX, (uint8_t)1));
		break;
	case 1:
		i_error("%zu", MALLOC_ADD((uint8_t)1, (size_t)SIZE_MAX));
		break;
	}
	*stage -= 2;

	if (*stage >= N_ELEMENTS(add_tests)*2) {
		*stage -= N_ELEMENTS(add_tests)*2;
		if (*stage == 0)
			test_end();
		test_expect_fatal_string(NULL);
		return FATAL_TEST_FINISHED;
	}
	i = *stage / 2;

	if (*stage % 2 == 0)
		i_error("%zu", MALLOC_ADD(add_tests[i].a, add_tests[i].b));
	else
		i_error("%zu", MALLOC_ADD(add_tests[i].b, add_tests[i].a));
	return FATAL_TEST_FAILURE;
}

enum fatal_test_state fatal_malloc_overflow(unsigned int stage)
{
	enum fatal_test_state state;

	state = fatal_malloc_overflow_multiply(&stage);
	if (state != FATAL_TEST_FINISHED)
		return state;
	return fatal_malloc_overflow_add(&stage);
}
