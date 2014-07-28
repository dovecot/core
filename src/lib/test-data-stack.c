/* Copyright (c) 2014-2014 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "data-stack.h"
#include <stdlib.h>

static void test_ds_buffers(void)
{
	test_begin("data-stack buffer growth");
	T_BEGIN {
		size_t i;
		unsigned char *p;
		size_t left = t_get_bytes_available();
		while (left < 10000) {
			t_malloc(left); /* force a new block */
			left = t_get_bytes_available();
		}
		left -= 64; /* make room for the sentry if DEBUG */
		p = t_buffer_get(1);
		p[0] = 1;
		for (i = 2; i <= left; i++) {
			/* grow it */
			unsigned char *p2 = t_buffer_get(i);
			test_assert_idx(p == p2, i);
			p[i-1] = i;
			test_assert_idx(p[i-2] == (unsigned char)(i-1), i);
		}
		/* now fix it permanently */
		t_buffer_alloc_last_full();
		test_assert(t_get_bytes_available() < 64 + MEM_ALIGN(1));
	} T_END;
	test_end();

	test_begin("data-stack buffer interruption");
	T_BEGIN {
		void *b = t_buffer_get(1000);
		void *a = t_malloc(1);
		void *b2 = t_buffer_get(1001);
		test_assert(a == b); /* expected, not guaranteed */
		test_assert(b2 != b);
	} T_END;
	test_end();

	test_begin("data-stack buffer with reallocs");
	T_BEGIN {
		size_t bigleft = t_get_bytes_available();
		size_t i;
		for (i = 1; i < bigleft-64; i += rand()%32) T_BEGIN {
			unsigned char *p, *p2;
			size_t left;
			t_malloc(i);
			left = t_get_bytes_available();
			/* The most useful idx for the assert is 'left' */
			test_assert_idx(left <= bigleft-i, left);
			p = t_buffer_get(left/2);
			p[0] = 'Z'; p[left/2 - 1] = 'Z';
			p2 = t_buffer_get(left + left/2);
			test_assert_idx(p != p2, left);
			test_assert_idx(p[0] == 'Z', left);
			test_assert_idx(p[left/2 -1] == 'Z', left);
		} T_END;
	} T_END;
	test_end();
}

static void test_ds_recurse(int depth, int number, size_t size)
{
	int i;
	char **ps;
	char tag[2] = { depth+1, '\0' };
	int try_fails = 0;
	unsigned int t_id = t_push_named("test_ds_recurse[%i]", depth);
	ps = t_buffer_get_type(char *, number);
	test_assert_idx(ps != NULL, depth);
	t_buffer_alloc_type(char *, number);

	for (i = 0; i < number; i++) {
		ps[i] = t_malloc(size/2);
		bool re = t_try_realloc(ps[i], size);
		test_assert_idx(ps[i] != NULL, i);
		if (!re) {
			try_fails++;
			ps[i] = t_malloc(size);
		}
		/* drop our own canaries */
		memset(ps[i], tag[0], size);
		ps[i][size-2] = 0;
	}

	/* Now recurse... */
	if(depth>0)
		test_ds_recurse(depth-1, number, size);

	/* Test our canaries are still intact */
	for (i = 0; i < number; i++) {
		test_assert_idx(strspn(ps[i], tag) == size - 2, i);
		test_assert_idx(ps[i][size-1] == tag[0], i);
	}
	test_assert_idx(t_id == t_pop(), depth);
}

static void test_ds_recursive(int count, int depth)
{
	int i;

	test_begin("data-stack recursive");
	for(i = 0; i < count; i++) T_BEGIN {
			int number=rand()%100+50;
			int size=rand()%100+50;
			test_ds_recurse(depth, number, size);
		} T_END;
	test_end();
}

void test_data_stack(void)
{
	test_ds_buffers();
	test_ds_recursive(20, 80);
}
