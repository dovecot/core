/* Copyright (c) Dovecot authors, see top-level COPYING file */

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
	output_data = t_buffer_create(1024);
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

	test_assert(o_stream_finish(output) > 0);
	test_assert(output->offset == strlen(test->input));
	test_assert(test_output->offset == strlen(test->output));
	o_stream_unref(&output);
	o_stream_unref(&test_output);

	test_assert_ucmp(str_len(output_data), ==, strlen(test->output));
	test_assert_memcmp(str_c(output_data), str_len(output_data),
			   test->output, strlen(test->output));

	i_stream_unref(&test_input);
}

static void test_ostream_dot(void)
{
	static struct dot_test tests[] = {
		{ "foo\r\n.\r\n", "foo\r\n..\r\n.\r\n" },
		{ "foo\n.\n", "foo\r\n..\r\n.\r\n" },
		{ ".foo\r\n.\r\nfoo\r\n", "..foo\r\n..\r\nfoo\r\n.\r\n" },
		{ ".foo\n.\nfoo\n", "..foo\r\n..\r\nfoo\r\n.\r\n" },
		{
			"foo.\r\nfoo\r\n.foo\r\n.",
			"foo.\r\nfoo\r\n..foo\r\n..\r\n.\r\n"
		},
		{ ".", "..\r\n.\r\n" },
		{ "\r.", "\r\n..\r\n.\r\n" },
		{ "\r\r.", "\r\r\n..\r\n.\r\n" },
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

static void test_ostream_dot_parent_almost_full(void)
{
	buffer_t *output_data;
	struct ostream *test_output, *output;
	ssize_t ret;

	test_begin("dot ostream parent almost full");
	output_data = t_buffer_create(1024);
	test_output = test_ostream_create_nonblocking(output_data, 1);
	test_ostream_set_max_output_size(test_output, 1);

	output = o_stream_create_dot(test_output, FALSE);
	ret = o_stream_send(output, "a", 1);
	test_assert(ret == 0);
	ret = o_stream_send(output, "bc", 2);
	test_assert(ret == 0);
	o_stream_unref(&output);

	o_stream_unref(&test_output);
	test_end();
}

static void test_ostream_dot_parent_max_bytes_boundary(void)
{
	buffer_t *output_data;
	struct ostream *test_output, *output;
	ssize_t ret;

	test_begin("dot ostream parent exact fit");
	output_data = t_buffer_create(1024);
	test_output = test_ostream_create_nonblocking(output_data, 3);
	test_ostream_set_max_output_size(test_output, 3);

	output = o_stream_create_dot(test_output, FALSE);
	ret = o_stream_send(output, ".", 1);
	test_assert(ret == 1);
	test_assert_ucmp(output_data->used, ==, 2);
	test_assert_memcmp(output_data->data, output_data->used, "..", 2);

	o_stream_unref(&output);
	o_stream_unref(&test_output);
	test_end();
}

/* STATE_CR must persist across sendv calls so that a bare CR ending one send
   followed by '.' starting the next still triggers ADD_LF_DOT.
   A stateless per-call implementation would emit the '.' unguarded and let a
   downstream MTA that treats bare CR as EOL interpret it as end-of-DATA. */
static void test_ostream_dot_cr_across_sendv(void)
{
	buffer_t *output_data;
	struct ostream *test_output, *output;
	ssize_t ret;
	const char *expected = "\r\n..\r\n.\r\n";

	test_begin("dot ostream CR across sendv calls");
	output_data = t_buffer_create(1024);
	test_output = o_stream_create_buffer(output_data);

	output = o_stream_create_dot(test_output, FALSE);
	ret = o_stream_send(output, "\r", 1);
	test_assert(ret == 1);
	ret = o_stream_send(output, ".", 1);
	test_assert(ret == 1);
	test_assert(o_stream_finish(output) > 0);

	o_stream_unref(&output);
	o_stream_unref(&test_output);

	test_assert_ucmp(str_len(output_data), ==, strlen(expected));
	test_assert_memcmp(str_c(output_data), str_len(output_data),
	expected, strlen(expected));
	test_end();
}

/* Off-by-one regression guard for the bare-CR + '.' injection.
   Input "\r." places '.' at offset 1; the ADD_LF_DOT pair injects 3 bytes
   ("\n.."). The loop guard check becomes (1 + 3) <= max_bytes, so max_bytes==4
   is the exact-fit case. */
static void test_ostream_dot_cr_dot_exact_fit(void)
{
	buffer_t *output_data;
	struct ostream *test_output, *output;
	ssize_t ret;

	test_begin("dot ostream CR+dot exact fit");
	output_data = t_buffer_create(1024);
	test_output = test_ostream_create_nonblocking(output_data, 4);
	test_ostream_set_max_output_size(test_output, 4);

	output = o_stream_create_dot(test_output, FALSE);
	ret = o_stream_send(output, "\r.", 2);
	test_assert(ret == 2);
	test_assert_ucmp(output_data->used, ==, 4);
	test_assert_memcmp(output_data->data, output_data->used,
	"\r\n..", 4);

	o_stream_unref(&output);
	o_stream_unref(&test_output);
	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_ostream_dot,
		test_ostream_dot_parent_almost_full,
		test_ostream_dot_parent_max_bytes_boundary,
		test_ostream_dot_cr_across_sendv,
		test_ostream_dot_cr_dot_exact_fit,
		NULL
	};
	return test_run(test_functions);
}
