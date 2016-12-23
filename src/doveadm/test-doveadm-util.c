/* Copyright (c) 2016 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "test-common.h"
#include "doveadm-settings.h"
#include "doveadm-util.h"

struct doveadm_settings *doveadm_settings; /* just to avoid linker error */

static void test_i_strccdascmp(void)
{
	test_begin("i_strccdascmp()");

        test_assert(i_strccdascmp("", "")==0);
        test_assert(i_strccdascmp("", "-")!=0);
        test_assert(i_strccdascmp("-", "")!=0);
        test_assert(i_strccdascmp("-", "-")==0);
        test_assert(i_strccdascmp("-\0baz", "-\0bar")==0);
        test_assert(i_strccdascmp("", "a")!=0);
        test_assert(i_strccdascmp("a", "")!=0);
        test_assert(i_strccdascmp("a", "a")==0);
        test_assert(i_strccdascmp("a-", "a-")==0);
        test_assert(i_strccdascmp("a-a", "a-a")==0);
        test_assert(i_strccdascmp("ca", "ba")!=0);

        test_assert(i_strccdascmp("camel case", "camel case")==0);
        test_assert(i_strccdascmp("camel case", "camel-case")==0);
        test_assert(i_strccdascmp("camel case", "camelCase")==0);

        test_assert(i_strccdascmp("camel case", "camel-case")==0);
        test_assert(i_strccdascmp("camel-case", "camel-case")==0);
        test_assert(i_strccdascmp("camelCase", "camel-case")==0);

        test_assert(i_strccdascmp("camel case", "camel Case")==-i_strccdascmp("camel Case", "camel case"));
        test_assert(i_strccdascmp("camel-case", "camel Case")==-i_strccdascmp("camel Case", "camel-case"));
        test_assert(i_strccdascmp("camel dase", "camel case")==-i_strccdascmp("camel case", "camel dase"));

        test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_i_strccdascmp,
		NULL
	};
	return test_run(test_functions);
}
