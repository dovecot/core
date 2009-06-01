/* Copyright (c) 2007-2009 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "array.h"

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
	test_array_reverse();
}
