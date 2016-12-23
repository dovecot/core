/* Copyright (c) 2016 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "test-lib.h"
#include "dns-util.h"
#include "array.h"

static void test_dns_compare(void)
{
	static const struct {
		const char *a;
		const char *b;
		int res;
	} tests[] =
	{
		{ NULL, NULL, 0 },
		{ NULL, "", 1 },
		{ "", NULL, -1 },
		{ "", "", 0 },
		{ "a", "a", 0 },
		{ "a", "b", -1 },
		{ "b", "a", 1 },
		{ "A", "A", 0 },
		{ "A", "B", -1 },
		{ "B", "A", 1 },
		{ "A", "a", 0 },
		{ "a", "B", -1 },
		{ "B", "a", 1 },
		{ "test.invalid", "TeSt.InVaLid", 0 },
		{ "alphabet.com", "alpha.com", 52 },
		{ "com.alphabet", "com.alpha", 98 },
		{ "com.com", "com.comcom", -99 },
	};

	test_begin("test_dns_compare");

	for(size_t i = 0; i < N_ELEMENTS(tests); i++) {
		test_assert_idx(dns_compare(tests[i].a, tests[i].b) == tests[i].res, i);
		test_assert_idx(dns_compare_labels(tests[i].a, tests[i].b) == tests[i].res, i);
	}

	test_end();
}

static void test_dns_match(void)
{
	static const struct {
		const char *name;
		const char *mask;
		int res;
	} tests[] =
	{
		{ "", "", 0 },
		{ "", "*", 0 },
		{ "*", "", -1 },
		{ "TeSt.InVaLid", "test.invalid", 0 },
		{ "contoso.com", "test.invalid", -1 },
		{ "test.invalid", "test.unvalid", -1 },
		{ "name.test.invalid", "*.test.invalid", 0 },
		{ "real.name.test.invalid", "*.test.invalid", -1 },
		{ "real.name.test.invalid", "*.*.test.invalid", 0 },
		{ "name.test.invalid", "*name*.test.invalid", -1 },
		{ "name.invalid", "name.*", -1 },
	};

	test_begin("test_dns_match");

	for(size_t i = 0; i < N_ELEMENTS(tests); i++) {
		test_assert_idx(dns_match_wildcard(tests[i].name, tests[i].mask) == tests[i].res, i);
	}

	test_end();
}

static int
arr_dns_compare(const char *const *a, const char *const *b)
{
	return dns_compare_labels(*a,*b);
}

static void test_dns_sort(void)
{
	const char *input[] = {
		"test.invalid",
		"test.com",
		"test.contoso.com",
		"test.alphabet.com",
		"test.xxx",
	};

	const char *output[] = {
		"test.alphabet.com",
		"test.contoso.com",
		"test.com",
		"test.invalid",
		"test.xxx",
	};

	test_begin("test_dns_sort");

	ARRAY_TYPE(const_string) arr;
	t_array_init(&arr, 8);

	array_append(&arr, input, N_ELEMENTS(input));

	array_sort(&arr, arr_dns_compare);

	for(size_t i = 0; i < N_ELEMENTS(output); i++) {
		const char *const *strp = array_idx(&arr, i);
		test_assert_idx(dns_compare(*strp, output[i]) == 0, i);
	}

	test_end();
}

int main(void) {
	void (*test_functions[])(void) = {
		test_dns_compare,
		test_dns_match,
		test_dns_sort,
		NULL
	};
	return test_run(test_functions);
}
