/* Copyright (c) 2009-2011 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "str.h"
#include "env-util.h"
#include "hostpid.h"
#include "var-expand.h"

struct var_expand_test {
	const char *in;
	const char *out;
};

static void test_var_expand_builtin(void)
{
	static struct var_expand_test tests[] = {
		{ "%{hostname}", NULL },
		{ "%{pid}", NULL },
		{ "a%{env:FOO}b", "abaRb" }
	};
	static struct var_expand_table table[] = {
		{ '\0', NULL, NULL }
	};
	string_t *str = t_str_new(128);
	unsigned int i;

	tests[0].out = my_hostname;
	tests[1].out = my_pid;
	env_put("FOO=baR");

	test_begin("var_expand");
	for (i = 0; i < N_ELEMENTS(tests); i++) {
		str_truncate(str, 0);
		var_expand(str, tests[i].in, table);
		test_assert(strcmp(tests[i].out, str_c(str)) == 0);
	}
	test_end();
}

void test_var_expand(void)
{
	test_var_expand_builtin();
}
