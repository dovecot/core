/* Copyright (c) 2016-2017 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "str.h"
#include "istream-private.h"
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

void test_istream_sized(void)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(tests); i++) {
		test_begin(t_strdup_printf("istream sized %u", i+1));
		run_test(tests[i].input, tests[i].size, tests[i].stream_errno);
		test_end();
	}
}
