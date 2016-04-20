/* Copyright (c) 2009-2016 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "str.h"
#include "env-util.h"
#include "hostpid.h"
#include "var-expand.h"

struct var_expand_test {
	const char *in;
	const char *out;
};

struct var_get_key_range_test {
	const char *in;
	unsigned int idx, size;
};

static void test_var_expand_ranges(void)
{
	static struct var_expand_test tests[] = {
		{ "%v", "value1234" },
		{ "%3v", "val" },
		{ "%3.2v", "ue" },
		{ "%3.-2v", "ue12" },
		{ "%-3.2v", "23" },
		{ "%0.-1v", "value123" },
		{ "%-4.-1v", "123" }
	};
	static struct var_expand_table table[] = {
		{ 'v', "value1234", NULL },
		{ '\0', NULL, NULL }
	};
	string_t *str = t_str_new(128);
	unsigned int i;

	test_begin("var_expand - ranges");
	for (i = 0; i < N_ELEMENTS(tests); i++) {
		str_truncate(str, 0);
		var_expand(str, tests[i].in, table);
		test_assert(strcmp(tests[i].out, str_c(str)) == 0);
	}
	test_end();
}

static void test_var_expand_builtin(void)
{
	static struct var_expand_test tests[] = {
		{ "%{hostname}", NULL },
		{ "%{pid}", NULL },
		{ "a%{env:FOO}b", "abaRb" },
		{ "%50Hv", "1f" },
		{ "%50Hw", "2e" },
		{ "%50Nv", "25" },
		{ "%50Nw", "e" },

		{ "%{nonexistent}", "UNSUPPORTED_VARIABLE_nonexistent" },
		{ "%{nonexistent:default}", "UNSUPPORTED_VARIABLE_nonexistent" },
	};
	static struct var_expand_table table[] = {
		{ 'v', "value", NULL },
		{ 'w', "value2", NULL },
		{ '\0', NULL, NULL }
	};
	string_t *str = t_str_new(128);
	unsigned int i;

	tests[0].out = my_hostname;
	tests[1].out = my_pid;
	env_put("FOO=baR");

	test_begin("var_expand - builtin");
	for (i = 0; i < N_ELEMENTS(tests); i++) {
		str_truncate(str, 0);
		var_expand(str, tests[i].in, table);
		test_assert_idx(strcmp(tests[i].out, str_c(str)) == 0, i);
	}
	test_end();
}

static void test_var_get_key_range(void)
{
	static struct var_get_key_range_test tests[] = {
		{ "", 0, 0 },
		{ "{", 1, 0 },
		{ "k", 0, 1 },
		{ "{key}", 1, 3 },
		{ "5.5Rk", 4, 1 },
		{ "5.5R{key}", 5, 3 },
		{ "{key", 1, 3 }
	};
	unsigned int i, idx, size;

	test_begin("var_get_key_range");
	for (i = 0; i < N_ELEMENTS(tests); i++) {
		var_get_key_range(tests[i].in, &idx, &size);
		test_assert_idx(tests[i].idx == idx, i);
		test_assert_idx(tests[i].size == size, i);

		if (tests[i].size == 1)
			test_assert_idx(tests[i].in[idx] == var_get_key(tests[i].in), i);
	}
	test_end();
}

static const char *test_var_expand_func1(const char *data, void *context)
{
	test_assert(*(int *)context == 0xabcdef);
	return t_strdup_printf("<%s>", data);
}

static const char *test_var_expand_func2(const char *data ATTR_UNUSED,
					 void *context ATTR_UNUSED)
{
	return "";
}

static const char *test_var_expand_func3(const char *data ATTR_UNUSED,
					 void *context ATTR_UNUSED)
{
	return NULL;
}

static void test_var_expand_with_funcs(void)
{
	static struct var_expand_test tests[] = {
		{ "%{func1}", "<>" },
		{ "%{func1:foo}", "<foo>" },
		{ "%{func2}", "" },
		{ "%{func3}", "" }
	};
	static struct var_expand_table table[] = {
		{ '\0', NULL, NULL }
	};
	static const struct var_expand_func_table func_table[] = {
		{ "func1", test_var_expand_func1 },
		{ "func2", test_var_expand_func2 },
		{ "func3", test_var_expand_func3 },
		{ NULL, NULL }
	};
	string_t *str = t_str_new(128);
	unsigned int i;
	int ctx = 0xabcdef;

	test_begin("var_expand_with_funcs");
	for (i = 0; i < N_ELEMENTS(tests); i++) {
		str_truncate(str, 0);
		var_expand_with_funcs(str, tests[i].in, table, func_table, &ctx);
		test_assert_idx(strcmp(tests[i].out, str_c(str)) == 0, i);
	}
	test_end();
}

void test_var_expand(void)
{
	test_var_expand_ranges();
	test_var_expand_builtin();
	test_var_get_key_range();
	test_var_expand_with_funcs();
}
