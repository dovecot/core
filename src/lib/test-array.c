/* Copyright (c) 2007-2011 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "array.h"

struct foo {
	unsigned int a, b, c;
};

static void test_array_foreach(void)
{
	ARRAY_DEFINE(foos, struct foo);
	const struct foo *foo;
	struct foo nfoo;
	unsigned int i;

	test_begin("array foreach");
	t_array_init(&foos, 32);
	for (i = 0; i < 10; i++) {
		nfoo.a = nfoo.b = nfoo.c = i;
		array_append(&foos, &nfoo, 1);
	}

	array_foreach(&foos, foo) {
		i = array_foreach_idx(&foos, foo);
		test_assert(foo->a == i);
		test_assert(foo->b == i);
		test_assert(foo->c == i);
	}
	test_end();
}

static void test_array_reverse(void)
{
	ARRAY_DEFINE(intarr, int);
	int input[] = { -1234567890, -272585721, 2724859223U, 824725652 };
	const int *output;
	unsigned int i, j;

	test_begin("array reverse");
	t_array_init(&intarr, 5);
	for (i = 0; i < N_ELEMENTS(input); i++) {
		array_clear(&intarr);
		array_append(&intarr, input, i);
		array_reverse(&intarr);

		output = i == 0 ? NULL : array_idx(&intarr, 0);
		for (j = 0; j < i; j++)
			test_assert(input[i-j-1] == output[j]);
	}
	test_end();
}

void test_array(void)
{
	test_array_foreach();
	test_array_reverse();
}
