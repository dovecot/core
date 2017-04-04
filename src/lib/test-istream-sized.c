/* Copyright (c) 2016-2017 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "istream.h"
#include "istream-sized.h"

static const struct {
	const char *input;
	uoff_t size;
	int stream_errno;
} tests[] = {
	{ "", 0, 0 },
	{ "", 1, EPIPE },
	{ "a", 1, 0 },
	{ "ab", 1, EINVAL },
	{ "ab", 0, EINVAL },
	{ "ab", (uoff_t)-1, EPIPE },
};

static void
run_test(const char *sized_input, uoff_t sized_size, int stream_errno)
{
	unsigned int sized_input_len = strlen(sized_input);
	struct istream *input_data, *input;
	const unsigned char *data;
	size_t i, size;
	int ret = 0;

	input_data = test_istream_create_data(sized_input, sized_input_len);
	test_istream_set_allow_eof(input_data, FALSE);
	input = i_stream_create_sized(input_data, sized_size);

	for (i = 1; i < sized_input_len; i++) {
		test_istream_set_size(input_data, i);
		while ((ret = i_stream_read(input)) > 0) ;
		if (ret == -1 && stream_errno != 0)
			break;
		test_assert(ret == 0);
	}
	if (ret == 0) {
		test_istream_set_allow_eof(input_data, TRUE);
		test_istream_set_size(input_data, i);
		while ((ret = i_stream_read(input)) > 0) ;
	}
	test_assert(ret == -1);
	test_assert(input->stream_errno == stream_errno);

	data = i_stream_get_data(input, &size);
	test_assert(size == I_MIN(sized_input_len, sized_size));
	if (size > 0)
		test_assert(memcmp(data, sized_input, size) == 0);
	i_stream_unref(&input);
	i_stream_unref(&input_data);
}

static void test_istream_sized_full(bool exact)
{
	const unsigned char test_data[10] = "1234567890";
	struct istream *test_input, *input;
	unsigned int i, j;
	int expected_errno;

	for (i = 1; i < sizeof(test_data)*2; i++) {
		test_input = test_istream_create_data(test_data, sizeof(test_data));
		test_istream_set_allow_eof(test_input, FALSE);
		test_istream_set_size(test_input, 0);

		if (exact)
			input = i_stream_create_sized(test_input, i);
		else
			input = i_stream_create_min_sized(test_input, i);
		for (j = 1; j <= I_MIN(i, sizeof(test_data)); j++) {
			test_assert_idx(i_stream_read(input) == 0, j);
			test_istream_set_size(test_input, j);
			test_assert_idx(i_stream_read(input) == 1, j);
		}
		test_assert_idx(i_stream_read(input) == 0, i);
		if (j <= sizeof(test_data))
			test_istream_set_size(test_input, j);
		else
			test_istream_set_allow_eof(test_input, TRUE);
		test_assert_idx(i_stream_read(input) == -1 && input->eof, i);
		if (i > sizeof(test_data))
			expected_errno = EPIPE;
		else if (i < sizeof(test_data) && exact)
			expected_errno = EINVAL;
		else
			expected_errno = 0;
		test_assert_idx(input->stream_errno == expected_errno, i);
		i_stream_unref(&input);
		i_stream_unref(&test_input);
	}
}

void test_istream_sized(void)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(tests); i++) {
		test_begin(t_strdup_printf("istream sized %u", i+1));
		run_test(tests[i].input, tests[i].size, tests[i].stream_errno);
		test_end();
	}
	test_begin("istream sized");
	test_istream_sized_full(TRUE);
	test_end();

	test_begin("istream sized min");
	test_istream_sized_full(FALSE);
	test_end();
}
