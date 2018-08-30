/* Copyright (c) 2007-2018 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "array.h"


struct foo {
	unsigned int a, b, c;
};

static void test_array_count(void)
{
	ARRAY(struct foo) foos;
	struct foo nfoo;

	test_begin("array count/empty");
	t_array_init(&foos, 32);

	test_assert(array_count(&foos) == 0);
	test_assert(array_is_empty(&foos));
	test_assert(!array_not_empty(&foos));
	nfoo.a = nfoo.b = nfoo.c = 9;
	array_append(&foos, &nfoo, 1);
	test_assert(array_count(&foos) == 1);
	test_assert(!array_is_empty(&foos));
	test_assert(array_not_empty(&foos));

	test_end();
}
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
static void test_array_foreach_elem_struct(void)
{
	ARRAY(struct foo) foos;
	struct foo foo;
	unsigned int i;

	test_begin("array foreach_elem struct");
	t_array_init(&foos, 32);
	for (i = 0; i < 10; i++) {
		foo.a = foo.b = foo.c = i;
		array_append(&foos, &foo, 1);
	}

	i = 0;
	array_foreach_elem(&foos, foo) {
		test_assert_idx(foo.a == i, i);
		test_assert_idx(foo.b == i, i);
		test_assert_idx(foo.c == i, i);
		i++;
	}
	test_end();
}
static void test_array_foreach_elem_string(void)
{
	ARRAY(char *) blurbs;
	ARRAY(const char *) cblurbs;
	char *string;
	const char *cstring;
	int i;

	test_begin("array foreach_elem ro/rw strings");
	t_array_init(&blurbs, 32);
	t_array_init(&cblurbs, 32);
	for (i = 0; i < 10; i++) {
		cstring = t_strdup_printf("x%iy", i);
		string = (char *)cstring;
		array_append(&blurbs, &string, 1);
		array_append(&cblurbs, &cstring, 1);
	}

	i = 0;
	array_foreach_elem(&blurbs, string) {
		test_assert_idx(string[0] == 'x' && string[1]-'0' == i && string[2] == 'y', i);
		i++;
	}
	i = 0;
	array_foreach_elem(&cblurbs, cstring) {
		test_assert_idx(cstring[0] == 'x' && cstring[1]-'0' == i && cstring[2] == 'y', i);
		i++;
	}
	test_end();
}

static void test_array_swap(void)
{
	ARRAY(struct foo) foos[3];
	struct foo nfoo;
	int i, j;

	test_begin("array swap");
	for (i = 1; i <= 3; i++) {
		t_array_init(&foos[i-1], i);
		for (j = 1; j <= 2*i+1; j++) {
			nfoo.a = nfoo.b = nfoo.c = j;
			array_append(&foos[i-1], &nfoo, 1);
		}
	}
	for (i = 0; i < 1000; i++)
		array_swap(&foos[i_rand()%3], &foos[i_rand()%3]);
	/* Just want size 3, 5, and 7 in any order */
	test_assert(array_count(&foos[0]) * array_count(&foos[1]) * array_count(&foos[2]) == 3*5*7);
	test_assert(array_count(&foos[0]) + array_count(&foos[1]) + array_count(&foos[2]) == 3+5+7);
	test_end();
}

static int test_int_compare(const int *key, const int *elem)
{
	return (*key < *elem) ? -1 :
		(*key > *elem) ? 1 :
		0;
}
static void test_array_reverse(void)
{
	ARRAY(int) intarr;
	int input[] = { -1234567890, -272585721, 272485922, 824725652 };
	const int tmpi = 999, *output;
	unsigned int i, j;

	test_begin("array reverse");
	t_array_init(&intarr, 5);
	for (i = 0; i <= N_ELEMENTS(input); i++) {
		array_clear(&intarr);
		array_append(&intarr, input, i);
		array_reverse(&intarr);

		output = i == 0 ? NULL : array_idx(&intarr, 0);
		for (j = 0; j < i; j++)
			test_assert(input[i-j-1] == output[j]);
	}
	test_end();

	test_begin("array_lsearch");
	for (i = 0; i < N_ELEMENTS(input); i++) {
		output = array_lsearch(&intarr, &input[i], test_int_compare);
		test_assert(output != NULL);
		j = array_ptr_to_idx(&intarr, output);
		test_assert_idx(j == N_ELEMENTS(input) - 1 - i, i);
	}
	output = array_lsearch(&intarr, &tmpi, test_int_compare);
	test_assert(output == NULL);
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
		0x8000, 0xc000, 0xfe00, 0xff00, 0xff80, 0xffc0, 0xfffe, 0xffff,
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
		elems[i] = i_rand();
		array_append(&arr2, &elems[i], 1);
	}
	array_append(&arr1, elems, NELEMS);
	test_assert(array_cmp(&arr1, &arr2) == TRUE);
	test_assert(array_equal_fn(&arr1, &arr2, test_compare_ushort) == TRUE);
	fuzz = 0;
	test_assert(array_equal_fn_ctx(&arr1, &arr2, test_compare_ushort_fuzz, &fuzz) == TRUE);

	for (i = 0; i < 256; i++) {
		unsigned int j = i_rand() % NELEMS;
		const unsigned short *ptmp = array_idx(&arr2, j);
		unsigned short tmp = *ptmp;
		unsigned short repl = tmp + deltas[i_rand() % N_ELEMENTS(deltas)];

		array_idx_set(&arr2, j, &repl);
		test_assert_idx(array_cmp(&arr1, &arr2) == (tmp == repl), i);
		test_assert_idx(array_equal_fn(&arr1, &arr2, test_compare_ushort) == (tmp == repl), i);
		fuzz = (int)tmp - (int)repl;
		if (fuzz < 0)
			fuzz = -fuzz;
		test_assert_idx(array_equal_fn_ctx(&arr1, &arr2, test_compare_ushort_fuzz, &fuzz) == TRUE, i);
		if (fuzz > 0) {
			fuzz--;
			test_assert_idx(array_equal_fn_ctx(&arr1, &arr2, test_compare_ushort_fuzz, &fuzz) == FALSE, i);
		}
		array_idx_set(&arr2, j, &tmp);
		test_assert_idx(array_cmp(&arr1, &arr2) == TRUE, i);
		test_assert_idx(array_equal_fn(&arr1, &arr2, test_compare_ushort) == TRUE, i);
		fuzz = 0;
		test_assert_idx(array_equal_fn_ctx(&arr1, &arr2, test_compare_ushort_fuzz, &fuzz) == TRUE, i);
	}
	elems[NELEMS] = 0;
	array_append(&arr2, &elems[NELEMS], 1);
	test_assert(array_cmp(&arr1, &arr2) == FALSE);
	test_assert(array_equal_fn(&arr1, &arr2, test_compare_ushort) == FALSE);
	test_assert_idx(array_equal_fn_ctx(&arr1, &arr2, test_compare_ushort_fuzz, &fuzz) == FALSE, i);

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
		elemstrs[i] = t_strdup_printf("%x", i_rand()); /* never 0-length */
		array_append(&arr2, &elemstrs[i], 1);
	}
	array_append(&arr1, elemstrs, NELEMS);
	test_assert(array_cmp(&arr1, &arr2) == TRUE); /* pointers shared, so identical */
	test_assert(array_equal_fn(&arr1, &arr2, test_compare_string) == TRUE); /* therefore value same */
	for (i = 0; i < 2560; i++) {
		unsigned int j = i_rand() % NELEMS;
		const char *const *ostr_p = array_idx(&arr2, j);
		const char *ostr = *ostr_p;
		unsigned int olen = strlen(ostr);
		unsigned int rc = i_rand() % (olen + 1);
		char ochar = ostr[rc];
		char buf[12];
		const char *bufp = buf;
		memcpy(buf, ostr, olen+1);
		buf[rc] = i_rand() % (CHAR_MAX + 1 - CHAR_MIN) + CHAR_MIN;
		if(rc == olen)
			buf[rc+1] = '\0';
		array_idx_set(&arr2, j, &bufp);
		test_assert(array_cmp(&arr1, &arr2) == FALSE); /* pointers now differ */
		test_assert_idx(array_equal_fn(&arr1, &arr2, test_compare_string)
				== (strcmp(ostr, buf) == 0), i); /* sometimes still the same */
		test_assert_idx(array_equal_fn(&arr1, &arr2, test_compare_string)
				== (ochar == buf[rc]), i); /* ditto */
		array_idx_set(&arr2, j, &ostr);
		test_assert(array_cmp(&arr1, &arr2) == TRUE); /* pointers now same again */
		test_assert_idx(array_equal_fn(&arr1, &arr2, test_compare_string) == TRUE, i); /* duh! */
	}
	/* length differences being detected are tested in other tests */
	test_end();
}

static void
test_array_free_case(bool keep)
{
	pool_t pool = pool_allocfree_create("array test");
	ARRAY(int) r;
	int *p;

	test_begin(keep ? "array_free" : "array_free_without_data");

	p_array_init(&r, pool, 100);
	p = array_append_space(&r);
	if (keep) {
		p = array_free_without_data(&r);
		test_assert(pool_allocfree_get_total_used_size(pool)>=400);
		p_free(pool, p);
	} else {
		array_free(&r);
		test_assert(pool_allocfree_get_total_used_size(pool)==0);
	}
	pool_unref(&pool);
	test_end();
}
static void
test_array_free(void)
{
	test_array_free_case(FALSE);
	test_array_free_case(TRUE);
}

void test_array(void)
{
	test_array_count();
	test_array_foreach();
	test_array_foreach_elem_struct();
	test_array_foreach_elem_string();
	test_array_reverse();
	test_array_cmp();
	test_array_cmp_str();
	test_array_swap();
	test_array_free();
}

enum fatal_test_state fatal_array(unsigned int stage)
{
	double tmpd[2] = { 42., -42. };
	short tmps[8] = {1,2,3,4,5,6,7,8};
	static const void *useless_ptr; /* persuade gcc to not optimise the tests */

	switch(stage) {
	case 0: {
		ARRAY(double) ad;
		test_begin("fatal_array");
		t_array_init(&ad, 3);
		/* allocation big enough, but memory not initialised */
		test_expect_fatal_string("(array_idx_i): assertion failed: (idx * array->element_size < array->buffer->used)");
		useless_ptr = array_idx(&ad, 0);
		return FATAL_TEST_FAILURE;
	}

	case 1: {
		ARRAY(double) ad;
		t_array_init(&ad, 2);
		array_append(&ad, tmpd, 2);
		/* actual out of range address requested */
		test_expect_fatal_string("(array_idx_i): assertion failed: (idx * array->element_size < array->buffer->used)");
		useless_ptr = array_idx(&ad, 2);
		return FATAL_TEST_FAILURE;
	}

	case 2: {
		ARRAY(double) ad;
		ARRAY(short) as;
		t_array_init(&ad, 2);
		t_array_init(&as, 8);
		array_append(&as, tmps, 2);
		/* can't copy different array sizes */
		test_expect_fatal_string("(array_copy): assertion failed: (dest->element_size == src->element_size)");
		array_copy(&ad.arr, 1, &as.arr, 0, 4);
		return FATAL_TEST_FAILURE;
	}
	}
	test_end();
	/* Forces the compiler to check the value of useless_ptr, so that it
	   must call array_idx (which is marked as pure, and gcc was desperate
	   to optimise out. Of course, gcc is unaware stage is never UINT_MAX.*/
	return (useless_ptr != NULL && stage == UINT_MAX)
		? FATAL_TEST_FAILURE : FATAL_TEST_FINISHED;
}
