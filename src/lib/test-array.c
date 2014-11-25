/* Copyright (c) 2007-2014 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "array.h"

#include <stdlib.h> /* rand() */

struct foo {
	unsigned int a, b, c;
};

static void test_array_foreach(void)
{
	ARRAY(struct foo) foos;
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
	ARRAY(int) intarr;
	int input[] = { -1234567890, -272585721, 272485922, 824725652 };
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

static void test_array_cmp(void)
{
	static const unsigned short deltas[] = {
		-32768, -16384, -512, -256, -128, -64, -2, -1,
		0, 1, 2, 64, 128, 256, 512, 16384, 32768
	};

#define NELEMS 5u
	ARRAY(unsigned short) arr1, arr2;
	unsigned short elems[NELEMS];
	unsigned int i;

	test_begin("array compare (ushort)");
	t_array_init(&arr1, NELEMS);
	t_array_init(&arr2, NELEMS);
	for (i = 0; i < NELEMS; i++) {
		elems[i] = rand();
		array_append(&arr2, &elems[i], 1);
	}
	array_append(&arr1, elems, NELEMS);
	test_assert(array_cmp(&arr1, &arr2) == 1);
	for (i = 0; i < 256; i++) {
		unsigned int j = rand() % NELEMS;
		unsigned short tmp = *array_idx(&arr2, j);
		unsigned short repl = tmp + deltas[rand() % N_ELEMENTS(deltas)];

		array_idx_set(&arr2, j, &repl);
		test_assert_idx(array_cmp(&arr1, &arr2) == (tmp == repl), i);
		array_idx_set(&arr2, j, &tmp);
		test_assert_idx(array_cmp(&arr1, &arr2) == TRUE, i);
	}
	test_end();
}

void test_array(void)
{
	test_array_foreach();
	test_array_reverse();
	test_array_cmp();
}
