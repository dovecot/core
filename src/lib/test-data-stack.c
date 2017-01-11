/* Copyright (c) 2014-2017 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "data-stack.h"

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

static void test_ds_realloc()
{
	test_begin("data-stack realloc");
	T_BEGIN {
		size_t i;
		unsigned char *p;
		size_t left = t_get_bytes_available();
		while (left < 10000) {
			t_malloc(left); /* force a new block */
			left = t_get_bytes_available();
		}
		left -= 64; /* make room for the sentry if DEBUG */
		p = t_malloc(1);
		p[0] = 1;
		for (i = 2; i <= left; i++) {
			/* grow it */
			test_assert_idx(t_try_realloc(p, i), i);
			p[i-1] = i;
			test_assert_idx(p[i-2] == (unsigned char)(i-1), i);
		}
		test_assert(t_get_bytes_available() < 64 + MEM_ALIGN(1));
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
	ps = t_buffer_get(sizeof(char *) * number);
	i_assert(ps != NULL);
	t_buffer_alloc(sizeof(char *) * number);

	for (i = 0; i < number; i++) {
		ps[i] = t_malloc(size/2);
		bool re = t_try_realloc(ps[i], size);
		i_assert(ps[i] != NULL);
		if (!re) {
			try_fails++;
			ps[i] = t_malloc(size);
		}
		/* drop our own canaries */
		memset(ps[i], tag[0], size);
		ps[i][size-2] = 0;
	}
	/* Do not expect a high failure rate from t_try_realloc */
	test_assert_idx(try_fails <= number / 20, depth);

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
	test_ds_realloc();
	test_ds_recursive(20, 80);
}

enum fatal_test_state fatal_data_stack(unsigned int stage)
{
#ifdef DEBUG
	/* If we abort, then we'll be left with a dangling t_push()
	   keep a record of our temporary stack id, so we can clean up. */
	static unsigned int t_id = 999999999;
	static unsigned char *undo_ptr = NULL;
	static unsigned char undo_data;
	static bool things_are_messed_up = FALSE;
	if (stage != 0) {
		/* Presume that we need to clean up from the prior test:
		   undo the evil write, then we will be able to t_pop cleanly,
		   and finally we can end the test stanza. */
		if (things_are_messed_up || undo_ptr == NULL)
			return FATAL_TEST_ABORT; /* abort, things are messed up with t_pop */
		*undo_ptr = undo_data;
		undo_ptr = NULL;
		/* t_pop musn't abort, that would cause recursion */
		things_are_messed_up = TRUE;
		if (t_id != 999999999 && t_pop() != t_id)
			return FATAL_TEST_ABORT; /* abort, things are messed up with us */
		things_are_messed_up = FALSE;
		t_id = 999999999;
		test_end();
	}

	switch(stage) {
	case 0: {
		unsigned char *p;
		test_begin("fatal data-stack underrun");
		t_id = t_push_named("fatal_data_stack underrun");
		size_t left = t_get_bytes_available();
		p = t_malloc(left-80); /* will fit */
		p = t_malloc(100); /* won't fit, will get new block */
		int seek = 0;
		/* Seek back for the canary, don't assume endianness */
		while(seek > -60 &&
		      ((p[seek+1] != 0xDB) ||
		       ((p[seek]   != 0xBA || p[seek+2] != 0xAD) &&
			(p[seek+2] != 0xBA || p[seek]   != 0xAD))))
			seek--;
		if (seek <= -60)
			return FATAL_TEST_ABORT; /* abort, couldn't find header */
		undo_ptr = p + seek;
		undo_data = *undo_ptr;
		*undo_ptr = '*';
		/* t_malloc will panic block header corruption */
		(void)t_malloc(10);
		return FATAL_TEST_FAILURE;
	}

	case 1: case 2: {
		test_begin(stage == 1 ? "fatal t_malloc overrun near" : "fatal t_malloc overrun far");
		t_id = t_push_named(stage == 1 ? "fatal t_malloc overrun first" : "fatal t_malloc overrun far");
		unsigned char *p = t_malloc(10);
		undo_ptr = p + 10 + (stage == 1 ? 0 : 8*4-1); /* presumes sentry size */
		undo_data = *undo_ptr;
		*undo_ptr = '*';
		/* t_pop will now fail */
		(void)t_pop();
		t_id = 999999999; /* We're FUBAR, mustn't pop next entry */
		return FATAL_TEST_FAILURE;
	}

	case 3: case 4: {
		test_begin(stage == 3 ? "fatal t_buffer_get overrun near" : "fatal t_buffer_get overrun far");
		t_id = t_push_named(stage == 3 ? "fatal t_buffer overrun near" : "fatal t_buffer_get overrun far");
		unsigned char *p = t_buffer_get(10);
		undo_ptr = p + 10 + (stage == 3 ? 0 : 8*4-1);
		undo_data = *undo_ptr;
		*undo_ptr = '*';
		/* t_pop will now fail */
		(void)t_pop();
		t_id = 999999999; /* We're FUBAR, mustn't pop next entry */
		return FATAL_TEST_FAILURE;
	}

	default:
		things_are_messed_up = TRUE;
		return FATAL_TEST_FINISHED;
	}
#else
	return stage == 0 ? FATAL_TEST_FINISHED : FATAL_TEST_ABORT;
#endif
}
