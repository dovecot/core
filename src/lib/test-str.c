/* Copyright (c) 2012 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "str.h"

static void test_str_c(void)
{
	string_t *str;
	unsigned int i, j;

	test_begin("str_c()");
	for (i = 0; i < 32; i++) T_BEGIN {
		str = t_str_new(15);
		for (j = 0; j < i; j++)
			str_append_c(str, 'x');
		T_BEGIN {
			(void)str_c(str);
		} T_END;
	} T_END;
	test_end();
}

void test_str(void)
{
	test_str_c();
}
