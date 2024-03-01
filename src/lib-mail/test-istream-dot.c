/* Copyright (c) 2007-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "istream.h"
#include "istream-dot.h"
#include "test-common.h"

enum outcome {
	END_OF_TESTS,
	NO_EOT,
	STRICT_EOT,
	LOOSE_EOT,
};

struct dot_test {
	enum outcome expected_outcome;
	const char *input;
	const char *output;
	const char *parent_input;
};

static void test_istream_dot_one(const struct dot_test *test,
				 enum istream_dot_flags flags,
				 bool test_bufsize)
{
	struct istream *test_input, *input;
	const unsigned char *data;
	size_t size;
	unsigned int i;
	size_t outsize, input_len, output_len;
	string_t *str;
	uoff_t offset;
	int ret;

	test_input = test_istream_create(test->input);
	input = i_stream_create_dot(test_input, flags);

	input_len = strlen(test->input);
	output_len = strlen(test->output);
	if (HAS_ANY_BITS(flags, ISTREAM_DOT_TRIM_TRAIL) &&
	    (test->input[input_len-1] == '\n' ||
	     strstr(test->input, "\n.\n") != NULL ||
	     strstr(test->input, "\n.\r\n") != NULL)) {
		if (output_len > 0 &&
		    test->output[output_len-1] == '\n') {
			output_len--;
			if (output_len > 0 &&
			    test->output[output_len-1] == '\r')
				output_len--;
		}
	}

	str = t_str_new(256);
	if (!test_bufsize) {
		outsize = 1; i = 0;
		i_stream_set_max_buffer_size(input, outsize);
		test_istream_set_size(test_input, 1);
		while ((ret = i_stream_read(input)) != -1) {
			switch (ret) {
			case -2:
				i_stream_set_max_buffer_size(input, ++outsize);
				offset = test_input->v_offset;
				/* seek one byte backwards so stream gets
				   reset */
				i_stream_seek(test_input, offset - 1);
				/* go back to original position */
				test_istream_set_size(test_input, offset);
				i_stream_skip(test_input, 1);
				/* and finally allow reading one more byte */
				test_istream_set_size(test_input, offset + 1);
				break;
			case 0:
				test_istream_set_size(test_input, ++i);
				break;
			default:
				test_assert(ret > 0);

				data = i_stream_get_data(input, &size);
				str_append_data(str, data, size);
				i_stream_skip(input, size);
			}
		}
		test_istream_set_size(test_input, input_len);
		(void)i_stream_read(test_input);
	} else {
		test_istream_set_size(test_input, input_len);
		size = 0;
		for (i = 1; i < output_len; i++) {
			i_stream_set_max_buffer_size(input, i);
			test_assert(i_stream_read(input) == 1);
			test_assert(i_stream_read(input) == -2);
			data = i_stream_get_data(input, &size);
			test_assert(memcmp(data, test->output, size) == 0);
		}
		i_stream_set_max_buffer_size(input, i+2);
		if (size < output_len)
			test_assert(i_stream_read(input) == 1);
		test_assert(i_stream_read(input) == -1);

		data = i_stream_get_data(input, &size);
		if (size > 0)
			str_append_data(str, data, size);
	}
	test_assert(input->stream_errno == 0);
	test_assert(str_len(str) == output_len);
	test_assert(memcmp(str_data(str), test->output, output_len) == 0);

	/* read the data after the '.' line and verify it's still there */
	i_stream_set_max_buffer_size(test_input, SIZE_MAX);
	(void)i_stream_read(test_input);
	data = i_stream_get_data(test_input, &size);
	test_assert(size == strlen(test->parent_input));
	if (size > 0)
		test_assert(memcmp(data, test->parent_input, size) == 0);

	i_stream_unref(&test_input);
	i_stream_unref(&input);
}

static void test_istream_dot_error(const char *input_str,
				   enum istream_dot_flags flags,
				   bool test_bufsize)
{
	struct istream *test_input, *input;
	unsigned int i;
	size_t outsize, input_len;
	uoff_t offset;
	int ret;

	test_input = test_istream_create(input_str);
	input = i_stream_create_dot(test_input, flags);

	input_len = strlen(input_str);

	if (!test_bufsize) {
		outsize = 1; i = 0;
		i_stream_set_max_buffer_size(input, outsize);
		test_istream_set_size(test_input, 1);
		while ((ret = i_stream_read(input)) != -1) {
			switch (ret) {
			case -2:
				i_stream_set_max_buffer_size(input, ++outsize);
				offset = test_input->v_offset;
				/* seek one byte backwards so stream gets
				   reset */
				i_stream_seek(test_input, offset - 1);
				/* go back to original position */
				test_istream_set_size(test_input, offset);
				i_stream_skip(test_input, 1);
				/* and finally allow reading one more byte */
				test_istream_set_size(test_input, offset + 1);
				break;
			case 0:
				test_istream_set_size(test_input, ++i);
				break;
			default:
				test_assert(ret > 0);
			}
		}
		test_istream_set_size(test_input, input_len);
		(void)i_stream_read(test_input);
	} else {
		test_istream_set_size(test_input, input_len);
		for (i = 1; i <= input_len; i++) {
			i_stream_set_max_buffer_size(input, i);
			(void)i_stream_read(input);
			(void)i_stream_read(input);
		}
		i_stream_set_max_buffer_size(input, i+1);
		(void)i_stream_read(input);
	}
	test_assert(input->stream_errno == EPIPE);

	i_stream_unref(&test_input);
	i_stream_unref(&input);
}

static const struct dot_test tests[] = {
	{ LOOSE_EOT, "..foo\n..\n.foo\n.\nfoo", ".foo\n.\nfoo\n", "foo" },
	{ LOOSE_EOT, "\r\n.\rfoo\n.\n", "\r\n\rfoo\n", "" },
	{ LOOSE_EOT, "\n.\r\n", "\n", "" },
	{ LOOSE_EOT, "\n.\n", "\n", "" },
	{ LOOSE_EOT, ".\n", "", "" },

	{ STRICT_EOT, "..foo\r\n..\r\n.foo\r\n.\r\nfoo", ".foo\r\n.\r\nfoo\r\n", "foo" },
	{ STRICT_EOT, "\r.\r\n.\r\n", "\r.\r\n", "" },
	{ STRICT_EOT, "\n\r.\r\r\n.\r\n", "\n\r.\r\r\n", "" },
	{ STRICT_EOT, "\r\n.\r\n", "\r\n", "" },
	{ STRICT_EOT, ".\r\n", "", "" },

	{ NO_EOT, "", NULL, NULL },
	{ NO_EOT, ".", NULL, NULL },
	{ NO_EOT, "..", NULL, NULL },
	{ NO_EOT, ".\r", NULL, NULL },
	{ NO_EOT, ".\rx", NULL, NULL },
	{ NO_EOT, "..\r\n", NULL, NULL },
	{ NO_EOT, "\r.", NULL, NULL },
	{ NO_EOT, "\r.\r", NULL, NULL },
	{ NO_EOT, "\r.\rx", NULL, NULL },
	{ NO_EOT, "\r.\r\n", NULL, NULL },
	{ NO_EOT, "\r.\n", NULL, NULL },
	{ NO_EOT, "\r..\n", NULL, NULL },
	{ NO_EOT, "\r\n", NULL, NULL },
	{ NO_EOT, "\r\n.", NULL, NULL },
	{ NO_EOT, "\r\n.\r", NULL, NULL },
	{ NO_EOT, "\r\n.\rx", NULL, NULL },
	{ NO_EOT, "\r\n.\rx\n", NULL, NULL },
	{ NO_EOT, "\r\n..\r\n", NULL, NULL },
	{ NO_EOT, "\n", NULL, NULL },
	{ NO_EOT, "\n.", NULL, NULL },
	{ NO_EOT, "\n.\r", NULL, NULL },
	{ NO_EOT, "\n.\rx", NULL, NULL },
	{ NO_EOT, "\n..\r\n", NULL, NULL },
	{ NO_EOT, "..foo\r\nbar\r\nbaz", NULL, NULL },

	{ END_OF_TESTS, NULL, NULL, NULL }
};

static void test_istream_dot(const char *test_name, enum istream_dot_flags flags)
{

	test_begin(test_name);
	for (const struct dot_test *test = tests; test->expected_outcome != END_OF_TESTS; test++) {
		bool expect_error;
		switch (test->expected_outcome) {
		case NO_EOT:
			expect_error = TRUE;
			break;
		case STRICT_EOT:
			expect_error = FALSE;
			break;
		case LOOSE_EOT:
			expect_error = !HAS_ANY_BITS(flags, ISTREAM_DOT_LOOSE_EOT);
			break;
		default:
			i_unreached();
		}

		if (expect_error) {
			test_istream_dot_error(test->input, flags, FALSE);
			test_istream_dot_error(test->input, flags, TRUE);
		} else {
			test_istream_dot_one(test, flags | ISTREAM_DOT_NO_TRIM, TRUE);
			test_istream_dot_one(test, flags | ISTREAM_DOT_NO_TRIM, FALSE);
			test_istream_dot_one(test, flags | ISTREAM_DOT_TRIM_TRAIL, TRUE);
			test_istream_dot_one(test, flags | ISTREAM_DOT_TRIM_TRAIL, FALSE);
		}
	}
	test_end();
}

static void test_istream_dot_accept_bare_lf(void)
{
	test_istream_dot("dot istream accept bare lf", ISTREAM_DOT_LOOSE_EOT);
}

static void test_istream_dot_strict(void)
{
	test_istream_dot("dot istream strict", ISTREAM_DOT_STRICT_EOT);
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_istream_dot_accept_bare_lf,
		test_istream_dot_strict,
		NULL,
	};
	return test_run(test_functions);
}
