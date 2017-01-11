/* Copyright (c) 2013-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "str.h"
#include "istream.h"
#include "ostream.h"
#include "ostream-dot.h"
#include "test-common.h"

struct dot_test {
	const char *input;
	const char *output;
};

static void test_ostream_dot_one(const struct dot_test *test)
{
	struct istream *test_input;
	struct ostream *output, *test_output;
	buffer_t *output_data;
	const unsigned char *data;
	size_t size;
	ssize_t ret;

	test_input = test_istream_create(test->input);
	output_data = buffer_create_dynamic(pool_datastack_create(), 1024);
	test_output = o_stream_create_buffer(output_data);

	output = o_stream_create_dot(test_output, FALSE);

	while ((ret = i_stream_read(test_input)) > 0 || ret == -2) {
		data = i_stream_get_data(test_input, &size);
		ret = o_stream_send(output, data, size);
		test_assert(ret >= 0);
		if (ret <= 0)
			break;
		i_stream_skip(test_input, ret);
	}

	test_assert(test_input->eof);

	test_assert(o_stream_flush(output) > 0);
	o_stream_unref(&output);
	o_stream_unref(&test_output);

	test_assert(strcmp(str_c(output_data), test->output) == 0);

	i_stream_unref(&test_input);
}

static void test_ostream_dot(void)
{
	static struct dot_test tests[] = {
		{ "foo\r\n.\r\n", "foo\r\n..\r\n.\r\n" },
		{ "foo\n.\n", "foo\r\n..\r\n.\r\n" },
		{ ".foo\r\n.\r\nfoo\r\n", "..foo\r\n..\r\nfoo\r\n.\r\n" },
		{ ".foo\n.\nfoo\n", "..foo\r\n..\r\nfoo\r\n.\r\n" },
		{ "\r\n", "\r\n.\r\n" },
		{ "\n", "\r\n.\r\n" },
		{ "", "\r\n.\r\n" },
	};
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(tests); i++) {
		test_begin(t_strdup_printf("dot ostream[%d]:", i));
		test_ostream_dot_one(&tests[i]);
		test_end();
	}
}

int main(void)
{
	static void (*test_functions[])(void) = {
		test_ostream_dot,
		NULL
	};
	return test_run(test_functions);
}
