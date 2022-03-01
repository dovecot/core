/* Copyright (c) 2014-2018 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "lib-event-private.h"
#include "event-filter.h"
#include "data-stack.h"

static int ds_grow_event_count = 0;

static bool
test_ds_grow_event_callback(struct event *event,
			    enum event_callback_type type,
			    struct failure_context *ctx,
			    const char *fmt ATTR_UNUSED,
			    va_list args ATTR_UNUSED)
{
	const struct event_field *field;

	if (type != EVENT_CALLBACK_TYPE_SEND)
		return TRUE;

	ds_grow_event_count++;
	test_assert(ctx->type == LOG_TYPE_DEBUG);

	field = event_find_field_nonrecursive(event, "alloc_size");
	test_assert(field != NULL &&
		    field->value_type == EVENT_FIELD_VALUE_TYPE_INTMAX &&
		    field->value.intmax >= 1024 * (5 + 100));
	field = event_find_field_nonrecursive(event, "used_size");
	test_assert(field != NULL &&
		    field->value_type == EVENT_FIELD_VALUE_TYPE_INTMAX &&
		    field->value.intmax >= 1024 * (5 + 100));
	field = event_find_field_nonrecursive(event, "last_alloc_size");
	test_assert(field != NULL &&
		    field->value_type == EVENT_FIELD_VALUE_TYPE_INTMAX &&
		    field->value.intmax >= 1024 * 100);
	field = event_find_field_nonrecursive(event, "frame_marker");
	test_assert(field != NULL &&
		    field->value_type == EVENT_FIELD_VALUE_TYPE_STR &&
		    strstr(field->value.str, "data-stack.c") != NULL);
	return TRUE;
}

static void test_ds_grow_event(void)
{
	const char *error;

	test_begin("data-stack grow event");
	event_register_callback(test_ds_grow_event_callback);

	i_assert(event_get_global_debug_log_filter() == NULL);
	struct event_filter *filter = event_filter_create();
	test_assert(event_filter_parse("event=data_stack_grow", filter, &error) == 0);
	event_set_global_debug_log_filter(filter);
	event_filter_unref(&filter);

	/* make sure the test won't fail due to earlier data stack
	   allocations. */
	data_stack_free_unused();
	T_BEGIN {
		(void)t_malloc0(1024*5);
		test_assert(ds_grow_event_count == 0);
		(void)t_malloc0(1024*100);
		test_assert(ds_grow_event_count == 1);
	} T_END;
	event_unset_global_debug_log_filter();
	event_unregister_callback(test_ds_grow_event_callback);
	test_end();
}

static void test_ds_get_used_size(void)
{
	test_begin("data-stack data_stack_get_used_size()");
	size_t size1 = data_stack_get_used_size();
	(void)t_malloc0(500);
	size_t size2 = data_stack_get_used_size();
	test_assert(size1 + 500 <= size2);

	T_BEGIN {
		(void)t_malloc0(300);
		size_t sub_size1 = data_stack_get_used_size();
		T_BEGIN {
			(void)t_malloc0(300);
		} T_END;
		test_assert_cmp(sub_size1, ==, data_stack_get_used_size());
	} T_END;
	test_assert_cmp(size2, ==, data_stack_get_used_size());
	test_end();
}

static void test_ds_get_bytes_available(void)
{
	test_begin("data-stack t_get_bytes_available()");
	for (unsigned int i = 0; i < 32; i++) {
		size_t orig_avail = t_get_bytes_available();
		size_t avail1;
		T_BEGIN {
			if (i > 0)
				t_malloc_no0(i);
			avail1 = t_get_bytes_available();
			t_malloc_no0(avail1);
			test_assert_idx(t_get_bytes_available() == 0, i);
			t_malloc_no0(1);
			test_assert_idx(t_get_bytes_available() > 0, i);
		} T_END;
		T_BEGIN {
			if (i > 0)
				t_malloc_no0(i);
			size_t avail2 = t_get_bytes_available();
			test_assert_idx(avail1 == avail2, i);
			t_malloc_no0(avail2 + 1);
			test_assert_idx(t_get_bytes_available() > 0, i);
		} T_END;
		test_assert_idx(t_get_bytes_available() == orig_avail, i);
	}
	test_end();
}

static void ATTR_FORMAT(2, 0)
test_ds_growing_debug(const struct failure_context *ctx ATTR_UNUSED,
		      const char *format, va_list args)
{
	ds_grow_event_count++;
	(void)t_strdup_vprintf(format, args);
}

static void test_ds_grow_in_event(void)
{
	size_t i, alloc1 = 8096;
	unsigned char *buf;
	const char *error;

	test_begin("data-stack grow in event");

	struct event_filter *filter = event_filter_create();
	event_set_global_debug_log_filter(filter);
	test_assert(event_filter_parse("event=data_stack_grow", filter, &error) == 0);
	event_filter_unref(&filter);

	i_set_debug_handler(test_ds_growing_debug);
	buf = t_buffer_get(alloc1);
	for (i = 0; i < alloc1; i++)
		buf[i] = i & 0xff;

	test_assert(ds_grow_event_count == 0);
	buf = t_buffer_reget(buf, 65536);
	test_assert(ds_grow_event_count == 1);
	for (i = 0; i < alloc1; i++) {
		if (buf[i] != (unsigned char)i)
			break;
	}
	test_assert(i == alloc1);

	i_set_debug_handler(default_error_handler);
	event_unset_global_debug_log_filter();
	test_end();
}

static void test_ds_buffers(void)
{
	test_begin("data-stack buffer growth");
	T_BEGIN {
		size_t i;
		unsigned char *p;
		size_t left = t_get_bytes_available();
		while (left < 10000) {
			t_malloc_no0(left+1); /* force a new block */
			left = t_get_bytes_available();
		}
		left -= 64; /* make room for the sentry if DEBUG */
		p = t_buffer_get(1);
		p[0] = 1;
		for (i = 2; i <= left; i++) {
			/* grow it */
			unsigned char *p2 = t_buffer_get(i);
			test_assert_idx(p == p2, i);
			p[i-1] = i & 0xff;
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
		void *a = t_malloc_no0(1);
		void *b2 = t_buffer_get(1001);
		test_assert(a == b); /* expected, not guaranteed */
		test_assert(b2 != b);
	} T_END;
	test_end();

	test_begin("data-stack buffer with reallocs");
	T_BEGIN {
		size_t bigleft = t_get_bytes_available();
		size_t i;
		/* with DEBUG: the stack frame allocation takes 96 bytes
		   and malloc takes extra 40 bytes + alignment, so don't let
		   "i" be too high. */
		for (i = 1; i < bigleft-96-40-16; i += i_rand_limit(32)) T_BEGIN {
			unsigned char *p, *p2;
			size_t left;
			t_malloc_no0(i);
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
			t_malloc_no0(left+1); /* force a new block */
			left = t_get_bytes_available();
		}
		left -= 64; /* make room for the sentry if DEBUG */
		p = t_malloc_no0(1);
		p[0] = 1;
		for (i = 2; i <= left; i++) {
			/* grow it */
			test_assert_idx(t_try_realloc(p, i), i);
			p[i-1] = i & 0xff;
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
	data_stack_frame_t t_id = t_push_named("test_ds_recurse[%i]", depth);
	ps = t_buffer_get(sizeof(char *) * number);
	i_assert(ps != NULL);
	t_buffer_alloc(sizeof(char *) * number);

	for (i = 0; i < number; i++) {
		ps[i] = t_malloc_no0(size/2);
		bool re = t_try_realloc(ps[i], size);
		i_assert(ps[i] != NULL);
		if (!re) {
			try_fails++;
			ps[i] = t_malloc_no0(size);
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
	test_assert_idx(t_pop(&t_id), depth);
}

static void test_ds_recursive(void)
{
	int count = 20, depth = 80;
	int i;

	test_begin("data-stack recursive");
	size_t init_size = data_stack_get_used_size();
	for(i = 0; i < count; i++) T_BEGIN {
			int number=i_rand_limit(100)+50;
			int size=i_rand_limit(100)+50;
			test_ds_recurse(depth, number, size);
		} T_END;
	test_assert_cmp(init_size, ==, data_stack_get_used_size());
	test_end();
}

static void test_ds_pass_str(void)
{
	data_stack_frame_t frames[32*2 + 1]; /* BLOCK_FRAME_COUNT*2 + 1 */
	const char *strings[N_ELEMENTS(frames)];

	test_begin("data-stack pass string");
	for (unsigned int frame = 0; frame < N_ELEMENTS(frames); frame++) {
		frames[frame] = t_push("test");
		if (frame % 10 == 5) {
			/* increase block counts */
			(void)t_malloc_no0(1024*30);
			(void)t_malloc_no0(1024*30);
		}
		strings[frame] = t_strdup_printf("frame %d", frame);
		for (unsigned int i = 0; i <= frame; i++) {
			test_assert_idx(data_stack_frame_contains(&frames[frame], strings[i]) == (i == frame),
					frame * 100 + i);
		}
	}

	const char *last_str = strings[N_ELEMENTS(frames)-1];
	for (unsigned int frame = N_ELEMENTS(frames); frame > 0; ) {
		frame--;
		test_assert(t_pop_pass_str(&frames[frame], &last_str));
	}
	test_assert_strcmp(last_str, "frame 64");

	/* make sure the pass_condition works properly */
	const char *error, *orig_error, *orig2_error;
	T_BEGIN {
		(void)t_strdup("qwertyuiop");
		error = orig_error = t_strdup("123456");
	} T_END_PASS_STR_IF(TRUE, &error);

	orig2_error = orig_error;
	T_BEGIN {
		(void)t_strdup("abcdefghijklmnopqrstuvwxyz");
	} T_END_PASS_STR_IF(FALSE, &orig2_error);
	/* orig_error and orig2_error both point to freed data stack frame */
	test_assert(orig_error == orig2_error);
	/* the passed error is still valid though */
	test_assert_strcmp(error, "123456");

	test_end();
}

void test_data_stack(void)
{
	void (*tests[])(void) = {
		test_ds_grow_event,
		test_ds_get_used_size,
		test_ds_get_bytes_available,
		test_ds_grow_in_event,
		test_ds_buffers,
		test_ds_realloc,
		test_ds_recursive,
		test_ds_pass_str,
	};
	for (unsigned int i = 0; i < N_ELEMENTS(tests); i++) {
		ds_grow_event_count = 0;
		data_stack_free_unused();
		T_BEGIN {
			tests[i]();
		} T_END;
	}
}

enum fatal_test_state fatal_data_stack(unsigned int stage)
{
#ifdef DEBUG
#define NONEXISTENT_STACK_FRAME_ID (data_stack_frame_t)999999999
	/* If we abort, then we'll be left with a dangling t_push()
	   keep a record of our temporary stack id, so we can clean up. */
	static data_stack_frame_t t_id = NONEXISTENT_STACK_FRAME_ID;
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
		/* t_pop mustn't abort, that would cause recursion */
		things_are_messed_up = TRUE;
		if (t_id != NONEXISTENT_STACK_FRAME_ID && !t_pop(&t_id))
			return FATAL_TEST_ABORT; /* abort, things are messed up with us */
		things_are_messed_up = FALSE;
		t_id = NONEXISTENT_STACK_FRAME_ID;
		test_end();
	}

	switch(stage) {
	case 0: {
		unsigned char *p;
		test_begin("fatal data-stack underrun");
		t_id = t_push_named("fatal_data_stack underrun");
		size_t left = t_get_bytes_available();
		p = t_malloc_no0(left-80); /* will fit */
		p = t_malloc_no0(100); /* won't fit, will get new block */
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
		/* t_malloc_no0 will panic block header corruption */
		test_expect_fatal_string("Corrupted data stack canary");
		(void)t_malloc_no0(10);
		return FATAL_TEST_FAILURE;
	}

	case 1: case 2: {
		test_begin(stage == 1 ? "fatal t_malloc_no0 overrun near" : "fatal t_malloc_no0 overrun far");
		t_id = t_push_named(stage == 1 ? "fatal t_malloc_no0 overrun first" : "fatal t_malloc_no0 overrun far");
		unsigned char *p = t_malloc_no0(10);
		undo_ptr = p + 10 + (stage == 1 ? 0 : 8*4-1); /* presumes sentry size */
		undo_data = *undo_ptr;
		*undo_ptr = '*';
		/* t_pop will now fail */
		test_expect_fatal_string("buffer overflow");
		(void)t_pop(&t_id);
		t_id = NONEXISTENT_STACK_FRAME_ID; /* We're FUBAR, mustn't pop next entry */
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
		test_expect_fatal_string("buffer overflow");
		(void)t_pop(&t_id);
		t_id = NONEXISTENT_STACK_FRAME_ID; /* We're FUBAR, mustn't pop next entry */
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
