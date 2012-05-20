/* Copyright (c) 2009-2012 Dovecot authors, see the included COPYING file */

#include "test-lib.h"

#include <stdlib.h>

static void test_p_strarray_dup(void)
{
	const char *input[][3] = {
		{ NULL },
		{ "a", NULL },
		{ "foobar", NULL },
		{ "a", "foo", NULL }
	};
	const char **ret;
	unsigned int i, j;

	test_begin("p_strarray_dup");

	for (i = 0; i < N_ELEMENTS(input); i++) {
		ret = p_strarray_dup(default_pool, input[i]);
		for (j = 0; input[i][j] != NULL; j++) {
			test_assert(strcmp(input[i][j], ret[j]) == 0);
			test_assert(input[i][j] != ret[j]);
		}
		test_assert(ret[j] == NULL);
		i_free(ret);
	}
	test_end();
}

static void strsplit_verify(const char *str)
{
	T_BEGIN {
		const char **s1, **s2;
		unsigned int i;

		s1 = t_strsplit_tab(str);
		s2 = t_strsplit(str, "\t");
		for (i = 0; s1[i] != NULL; i++)
			test_assert(null_strcmp(s1[i], s2[i]) == 0);
		test_assert(s2[i] == NULL);
	} T_END;
}

static void test_t_strsplit_tab(void)
{
	char buf[4096];
	unsigned int i, j, max;

	test_begin("t_strsplit_tab");
	strsplit_verify("");
	strsplit_verify("\t");
	strsplit_verify("\t\t");
	strsplit_verify("foo");
	strsplit_verify("foo\tbar");
	strsplit_verify("foo\tbar\tbaz");
	strsplit_verify("foo\t\tbaz");
	buf[sizeof(buf)-1] = '\0';
	for (i = 0; i < sizeof(buf)-1; i++)
		buf[i] = '\t';
	strsplit_verify(buf);
	for (j = 0; j < 256; j++) {
		memset(buf, '\t', j);
		buf[j+1] = '\0';
		strsplit_verify(buf);
	}
	for (j = 0; j < 100; j++) {
		max = (rand() % sizeof(buf)) + 1;
		buf[--max] = '\0';
		for (i = 0; i < max; i++) {
			if (rand() % 10 == 0)
				buf[i] = '\t';
			else
				buf[i] = 'x';
		}
		strsplit_verify(buf);
	}
	test_end();
}

void test_strfuncs(void)
{
	test_p_strarray_dup();
	test_t_strsplit_tab();
}
