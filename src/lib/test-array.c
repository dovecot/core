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
static int test_compare_ushort(const unsigned short *c1, const unsigned short *c2)
{
	return *c1 > *c2 ? 1
		: *c1 < *c2 ? -1
		: 0;
}
static int test_compare_ushort_fuzz(const unsigned short *c1, const unsigned short *c2, const int *pfuzz)
{
	int d = (int)*c1 - (int)*c2;
	if (d <= *pfuzz && -d <= *pfuzz)
		return 0;
	return d;
}
static void test_array_cmp(void)
{
	static const unsigned short deltas[] = {
		-32768, -16384, -512, -256, -128, -64, -2, -1,
		0, 1, 2, 64, 128, 256, 512, 16384, 32768
	};

#define NELEMS 5u
	ARRAY(unsigned short) arr1, arr2;
	unsigned short elems[NELEMS+1];
	unsigned int i;
	int fuzz;

	test_begin("array compare (ushort)");
	t_array_init(&arr1, NELEMS);
	t_array_init(&arr2, NELEMS);
	for (i = 0; i < NELEMS; i++) {
		elems[i] = rand();
		array_append(&arr2, &elems[i], 1);
	}
	array_append(&arr1, elems, NELEMS);
	test_assert(array_cmp(&arr1, &arr2) == 1);
	test_assert(array_equal_fn(&arr1, &arr2, test_compare_ushort) == 1);
	fuzz = 0;
	test_assert(array_equal_fn_ctx(&arr1, &arr2, test_compare_ushort_fuzz, &fuzz) == 1);

	for (i = 0; i < 256; i++) {
		unsigned int j = rand() % NELEMS;
		unsigned short tmp = *array_idx(&arr2, j);
		unsigned short repl = tmp + deltas[rand() % N_ELEMENTS(deltas)];

		array_idx_set(&arr2, j, &repl);
		test_assert_idx(array_cmp(&arr1, &arr2) == (tmp == repl), i);
		test_assert_idx(array_equal_fn(&arr1, &arr2, test_compare_ushort) == (tmp == repl), i);
		fuzz = (int)tmp - (int)repl;
		if (fuzz < 0)
			fuzz = -fuzz;
		test_assert_idx(array_equal_fn_ctx(&arr1, &arr2, test_compare_ushort_fuzz, &fuzz) == 1, i);
		if (fuzz > 0) {
			fuzz--;
			test_assert_idx(array_equal_fn_ctx(&arr1, &arr2, test_compare_ushort_fuzz, &fuzz) == 0, i);
		}
		array_idx_set(&arr2, j, &tmp);
		test_assert_idx(array_cmp(&arr1, &arr2) == TRUE, i);
		test_assert_idx(array_equal_fn(&arr1, &arr2, test_compare_ushort) == 1, i);
		fuzz = 0;
		test_assert_idx(array_equal_fn_ctx(&arr1, &arr2, test_compare_ushort_fuzz, &fuzz) == 1, i);
	}
	elems[NELEMS] = 0;
	array_append(&arr2, &elems[NELEMS], 1);
	test_assert(array_cmp(&arr1, &arr2) == 0);
	test_assert(array_equal_fn(&arr1, &arr2, test_compare_ushort) == 0);
	test_assert_idx(array_equal_fn_ctx(&arr1, &arr2, test_compare_ushort_fuzz, &fuzz) == 0, i);

	test_end();
}

static int test_compare_string(const char *const *c1, const char *const *c2)
{
	return strcmp(*c1, *c2);
}
static void test_array_cmp_str(void)
{
#define NELEMS 5u
	ARRAY(const char *) arr1, arr2;
	const char *elemstrs[NELEMS+1];
	unsigned int i;

	test_begin("array compare (char*)");
	t_array_init(&arr1, NELEMS);
	t_array_init(&arr2, NELEMS);
	for (i = 0; i < NELEMS; i++) {
		elemstrs[i] = t_strdup_printf("%x", rand()); /* never 0-length */
		array_append(&arr2, &elemstrs[i], 1);
	}
	array_append(&arr1, elemstrs, NELEMS);
	test_assert(array_cmp(&arr1, &arr2) == 1); /* pointers shared, so identical */
	test_assert(array_equal_fn(&arr1, &arr2, test_compare_string) == 1); /* therefore value same */
	for (i = 0; i < 2560; i++) {
		unsigned int j = rand() % NELEMS;
		const char *ostr = *array_idx(&arr2, j);
		unsigned int olen = strlen(ostr);
		unsigned int rc = rand() % (olen + 1);
		char ochar = ostr[rc];
		char buf[12];
		const char *bufp = buf;
		memcpy(buf, ostr, olen+1);
		buf[rc] = rand() % (CHAR_MAX + 1 - CHAR_MIN) + CHAR_MIN;
		if(rc == olen)
			buf[rc+1] = '\0';
		array_idx_set(&arr2, j, &bufp);
		test_assert(array_cmp(&arr1, &arr2) == 0); /* pointers now differ */
		test_assert_idx(array_equal_fn(&arr1, &arr2, test_compare_string)
				== (strcmp(ostr, buf) == 0), i); /* sometimes still the same */
		test_assert_idx(array_equal_fn(&arr1, &arr2, test_compare_string)
				== (ochar == buf[rc]), i); /* ditto */
		array_idx_set(&arr2, j, &ostr);
		test_assert(array_cmp(&arr1, &arr2) == 1); /* pointers now same again */
		test_assert_idx(array_equal_fn(&arr1, &arr2, test_compare_string) == 1, i); /* duh! */
	}
	/* length differences being detected are tested in other tests */
	test_end();
}

void test_array(void)
{
	test_array_foreach();
	test_array_reverse();
	test_array_cmp();
	test_array_cmp_str();
}
