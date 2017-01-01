/* Copyright (c) 2009-2017 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "str.h"
#include "istream-private.h"
#include "istream-tee.h"


#define TEST_BUF_SIZE I_STREAM_MIN_SIZE
#define TEST_STR_LEN (TEST_BUF_SIZE*3)
#define CHILD_COUNT 5

static void test_istream_tee_tailing(const char *str)
{
	struct istream *test_input, *child_input[CHILD_COUNT];
	struct tee_istream *tee;
	unsigned int i, len, delta;

	test_input = test_istream_create(str);
	test_istream_set_max_buffer_size(test_input, TEST_BUF_SIZE);

	test_begin("istream tee tailing");
	tee = tee_i_stream_create(test_input);
	for (i = 0; i < CHILD_COUNT; i++)
		child_input[i] = tee_i_stream_create_child(tee);

	test_istream_set_allow_eof(test_input, FALSE);
	delta = 1;
	for (len = 1; len < TEST_BUF_SIZE; len += delta) {
		test_istream_set_size(test_input, len);
		for (i = 0; i < CHILD_COUNT; i++) {
			test_assert_idx(i_stream_read(child_input[i]) == (int)delta, len);
			test_assert_idx(!tee_i_stream_child_is_waiting(child_input[i]), len);
			test_assert_idx(i_stream_read(child_input[i]) == 0, len);
			test_assert_idx(!tee_i_stream_child_is_waiting(child_input[i]), len);
		}
		delta = rand() % 32; /* may stand still */
		if(delta > TEST_BUF_SIZE - len)
			delta = 1;
	}

	test_istream_set_size(test_input, len);
	for (i = 0; i < CHILD_COUNT; i++) {
		test_assert(i_stream_read(child_input[i]) == (int)delta);
		test_assert(i_stream_read(child_input[i]) == -2);
		test_assert(!tee_i_stream_child_is_waiting(child_input[i]));
	}

	delta = 1;
	while ((len += delta) <= TEST_STR_LEN) {
		unsigned int lagger = rand() % CHILD_COUNT;
		test_istream_set_size(test_input, len);
		for (i = 0; i < CHILD_COUNT; i++) {
			test_assert(i_stream_read(child_input[i]) == -2);
			test_assert(!tee_i_stream_child_is_waiting(child_input[i]));
		}
		for (i = 0; i < CHILD_COUNT; i++) {
			if (i == lagger)
				continue;
			i_stream_skip(child_input[i], delta);
			test_assert(i_stream_read(child_input[i]) == 0);
			test_assert(tee_i_stream_child_is_waiting(child_input[i]));
		}
		i_stream_skip(child_input[lagger], delta);
		for (i = 0; i < CHILD_COUNT; i++) {
			test_assert(i_stream_read(child_input[i]) == (int)delta);
			test_assert(i_stream_read(child_input[i]) == -2);
			test_assert(!tee_i_stream_child_is_waiting(child_input[i]));
		}
		delta = rand() % 31 + 1; /* mustn't stand still */
		if(delta > TEST_STR_LEN - len)
			delta = 1;
	}

	for (i = 0; i < CHILD_COUNT-1; i++) {
		i_stream_skip(child_input[i], 1);
		test_assert(i_stream_read(child_input[i]) == 0);
		test_assert(tee_i_stream_child_is_waiting(child_input[i]));
	}
	i_stream_skip(child_input[i], 1);
	test_assert(i_stream_read(child_input[i]) == 0);
	test_assert(!tee_i_stream_child_is_waiting(child_input[i]));

	test_istream_set_allow_eof(test_input, TRUE);
	for (i = 0; i < CHILD_COUNT; i++) {
		test_assert(i_stream_read(child_input[i]) == -1);
		i_stream_unref(&child_input[i]);
	}
	i_stream_unref(&test_input);

	test_end();
}

static void test_istream_tee_blocks(const char *str)
{
	struct istream *test_input, *child_input[CHILD_COUNT];
	struct tee_istream *tee;
	unsigned int i, j;

	test_input = test_istream_create(str);
	test_istream_set_max_buffer_size(test_input, TEST_BUF_SIZE);

	test_begin("istream tee blocks");
	tee = tee_i_stream_create(test_input);
	for (i = 0; i < CHILD_COUNT; i++)
		child_input[i] = tee_i_stream_create_child(tee);

	test_istream_set_allow_eof(test_input, FALSE);
	for (j = 1; j <= 3; j++) {
		test_istream_set_size(test_input, TEST_BUF_SIZE*j);
		for (i = 0; i < CHILD_COUNT; i++) {
			test_assert(i_stream_read(child_input[i]) == TEST_BUF_SIZE);
			i_stream_skip(child_input[i], TEST_BUF_SIZE);
		}
	}
	test_istream_set_allow_eof(test_input, TRUE);
	for (i = 0; i < CHILD_COUNT; i++) {
		test_assert(i_stream_read(child_input[i]) == -1);
		i_stream_unref(&child_input[i]);
	}
	i_stream_unref(&test_input);

	test_end();
}

void test_istream_tee(void)
{
	string_t *str;
	unsigned int i;

	str = str_new(default_pool, TEST_STR_LEN);
	for (i = 0; i < TEST_STR_LEN; i++)
		str_append_c(str, 'a' + i%26);

	test_istream_tee_tailing(str_c(str));
	test_istream_tee_blocks(str_c(str));

	str_free(&str);
}
