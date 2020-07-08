/* Copyright (c) 2014-2018 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "istream.h"
#include "istream-crlf.h"

static void test_istream_children(void)
{
	struct istream *parent, *child1, *child2;
	const unsigned char *data;
	size_t size;

	test_begin("istream children");

	parent = test_istream_create_data("123456789", 9);
	test_istream_set_max_buffer_size(parent, 3);

	child1 = i_stream_create_limit(parent, (uoff_t)-1);
	child2 = i_stream_create_limit(parent, (uoff_t)-1);

	/* child1 read beginning */
	test_assert(i_stream_read(child1) == 3);
	data = i_stream_get_data(child1, &size);
	test_assert(size == 3 && memcmp(data, "123", 3) == 0);
	i_stream_skip(child1, 3);
	/* child1 read middle.. */
	test_assert(i_stream_read(child1) == 3);
	data = i_stream_get_data(child1, &size);
	test_assert(size == 3 && memcmp(data, "456", 3) == 0);
	/* child2 read beginning.. */
	test_assert(i_stream_read(child2) == 3);
	data = i_stream_get_data(child2, &size);
	test_assert(size == 3 && memcmp(data, "123", 3) == 0);
	/* child1 check middle again.. the parent has been modified,
	   so it can't return the original data (without some code changes). */
	test_assert(i_stream_get_data_size(child1) == 0);
	i_stream_skip(child1, 3);
	/* child1 read end */
	test_assert(i_stream_read(child1) == 3);
	data = i_stream_get_data(child1, &size);
	test_assert(size == 3 && memcmp(data, "789", 3) == 0);
	i_stream_skip(child1, 3);
	test_assert(i_stream_read(child1) == -1);
	/* child2 check beginning again.. */
	test_assert(i_stream_get_data_size(child1) == 0);
	i_stream_skip(child2, 3);
	/* child2 read middle */
	test_assert(i_stream_read(child2) == 3);
	data = i_stream_get_data(child2, &size);
	test_assert(size == 3 && memcmp(data, "456", 3) == 0);
	i_stream_skip(child2, 3);

	i_stream_destroy(&child1);
	i_stream_destroy(&child2);
	i_stream_destroy(&parent);

	test_end();
}

static void test_istream_next_line_expect(struct istream *is, const char *expect,
					  unsigned int i)
{
	const char *line = i_stream_next_line(is);
	return test_assert_strcmp_idx(line, expect, i);
}

static void test_istream_next_line(void)
{
	/* single line cases */
#define TEST_CASE(a, s, b) { \
	.input = (const unsigned char*)((a)), .input_len = sizeof((a)), \
	.skip = s, \
	.output = b }
	const struct test_case_sl {
		const unsigned char *input;
		size_t input_len;
		size_t skip;
		const char *output;
	} test_cases_sl[] = {
		TEST_CASE("", 0, NULL),
		TEST_CASE("a\n", 1, ""),
		TEST_CASE("a\r\n", 0, "a"),
		TEST_CASE("a\r\n", 1, ""),
		TEST_CASE("a\r\n", 2, ""),
		TEST_CASE("hello\nworld\n", 6, "world"),
		TEST_CASE("hello\nworld", 6, NULL),
		TEST_CASE("hello\n\n\n\n", 6, ""),
		TEST_CASE("wrong\n\r\n\n", 0, "wrong"),
		TEST_CASE("wrong\n\r\r\n", 6, "\r"),
		TEST_CASE("wrong\n\r\r\n", 7, ""),
	};

	test_begin("i_stream_next_line");

	for(unsigned int i = 0; i < N_ELEMENTS(test_cases_sl); i++) {
		const struct test_case_sl *test_case = &test_cases_sl[i];
		struct istream *input =
			i_stream_create_copy_from_data(test_case->input, test_case->input_len);
		test_assert_idx(i_stream_read(input) >= 0 ||
				(input->stream_errno == 0 && input->eof), i);
		i_stream_skip(input, test_case->skip);
		test_assert_strcmp_idx(i_stream_next_line(input), test_case->output, i);
		test_assert_idx(input->stream_errno == 0, i);
		i_stream_unref(&input);

		input = test_istream_create_data(test_case->input, test_case->input_len);
		test_assert_idx(i_stream_read(input) >= 0 ||
				(input->stream_errno == 0 && input->eof), i);
		i_stream_skip(input, test_case->skip);
		test_assert_strcmp_idx(i_stream_next_line(input), test_case->output, i);
		test_assert_idx(input->stream_errno == 0, i);
		i_stream_unref(&input);
	}

#undef TEST_CASE
#define TEST_CASE(a) test_istream_create_data((a), sizeof(a))
	/* multiline tests */
	struct istream *is = TEST_CASE("\n\n\n\n\n\n");
	size_t i;
	test_assert(i_stream_read(is) >= 0 || (is->stream_errno == 0 && is->eof));
	for(i = 0; i < 6; i++)
		test_istream_next_line_expect(is, "", i);
	test_assert(is->stream_errno == 0);
	i_stream_unref(&is);

	is = TEST_CASE(
		"simple\r\n"
		"multiline\n"
		"test with\0"
		"some exciting\n"
		"things\r\n\0");
	test_assert(i_stream_read(is) >= 0 || (is->stream_errno == 0 && is->eof));
	test_istream_next_line_expect(is, "simple", 0);
	test_istream_next_line_expect(is, "multiline", 1);
	test_istream_next_line_expect(is, "test with", 2);
	test_istream_next_line_expect(is, "things", 3);
	test_istream_next_line_expect(is, NULL, 4);
	test_assert(is->stream_errno == 0);
	i_stream_unref(&is);

	is = TEST_CASE(
		"NUL\0"
		"test\n");
	test_assert(i_stream_read(is) >= 0 || (is->stream_errno == 0 && is->eof));
	test_istream_next_line_expect(is, "NUL", 0);
	test_istream_next_line_expect(is,  NULL, 1);
	test_assert(is->stream_errno == 0);
	i_stream_unref(&is);

	const char test_data_1[] =
		"this is some data\n"
		"written like this\n"
		"to attempt and induce\n"
		"errors or flaws\n";

	is = TEST_CASE(test_data_1);
	size_t n = 0;
	const char *const *lines = t_strsplit(test_data_1, "\n");
	for(i = 0; i < sizeof(test_data_1); i++) {
		test_istream_set_size(is, i);
		i_stream_read(is);
		const char *line = i_stream_next_line(is);
		if (line != NULL) {
			test_assert_strcmp_idx(lines[n], line, n);
			n++;
		}
	}
	test_assert(n == 4);
	test_assert(is->stream_errno == 0);
	i_stream_unref(&is);

	const char test_data_2[] =
		"this is some data\n"
		"written like this\n"
		"to attempt and induce\n"
		"errors or flaws";

	is = TEST_CASE(test_data_2);
	lines = t_strsplit(test_data_2, "\n");
	i_stream_set_return_partial_line(is, TRUE);
	n = 0;

	/* requires one extra read to get the last line */
	for(i = 0; i < sizeof(test_data_1) + 1; i++) {
		test_istream_set_size(is, I_MIN(sizeof(test_data_1), i));
		i_stream_read(is);
		const char *line = i_stream_next_line(is);
		if (line != NULL) {
			test_assert_strcmp_idx(lines[n], line, n);
			n++;
		}
		i_stream_read(is);
	}
	test_assert(n == 4);
	test_assert(is->stream_errno == 0);
	i_stream_unref(&is);

	const char test_data_3[] =
		"this is some data\r\n"
		"written like this\r\n"
		"to attempt and induce\r\n"
		"errors or flaws\r\n";

	struct istream *is_1 = TEST_CASE(test_data_3);
	is = i_stream_create_crlf(is_1);
	i_stream_unref(&is_1);

	lines = t_strsplit_spaces(test_data_3, "\r\n");
	n = 0;

	for(i = 0; i < sizeof(test_data_3); i++) {
		test_istream_set_size(is, i);
		i_stream_read(is);
		const char *line = i_stream_next_line(is);
		if (line != NULL) {
			test_assert_strcmp_idx(lines[n], line, n);
			n++;
		}
	}
	test_assert(n == 4);
	test_assert(is->stream_errno == 0);
	i_stream_unref(&is);

	test_end();
}

static void test_istream_read_next_line(void)
{
	/* single line cases */
#undef TEST_CASE
#define TEST_CASE(a, s, b) { \
	.input = (const unsigned char*)((a)), .input_len = sizeof((a)), \
	.skip = s, \
	.output = b }
	const struct test_case_sl {
		const unsigned char *input;
		size_t input_len;
		size_t skip;
		const char *output;
	} test_cases_sl[] = {
		TEST_CASE("", 0, NULL),
		TEST_CASE("a\n", 1, ""),
		TEST_CASE("a\r\n", 0, "a"),
		TEST_CASE("a\r\n", 1, ""),
		TEST_CASE("a\r\n", 2, ""),
		TEST_CASE("hello\nworld\n", 6, "world"),
		TEST_CASE("hello\nworld", 6, NULL),
		TEST_CASE("hello\n\n\n\n", 6, ""),
		TEST_CASE("wrong\n\r\n\n", 0, "wrong"),
		TEST_CASE("wrong\n\r\r\n", 6, "\r"),
		TEST_CASE("wrong\n\r\r\n", 7, ""),
	};

	test_begin("i_stream_read_next_line");
	for(unsigned int i = 0; i < N_ELEMENTS(test_cases_sl); i++) {
		const struct test_case_sl *test_case = &test_cases_sl[i];
		struct istream *input =
			i_stream_create_copy_from_data(test_case->input, test_case->input_len);
		i_stream_skip(input, test_case->skip);
		test_assert_strcmp_idx(i_stream_read_next_line(input), test_case->output, i);
		test_assert_idx(input->stream_errno == 0, i);
		i_stream_unref(&input);

		input = test_istream_create_data(test_case->input, test_case->input_len);
		i_stream_skip(input, test_case->skip);
		test_assert_strcmp_idx(i_stream_read_next_line(input), test_case->output, i);
		test_assert_idx(input->stream_errno == 0, i);
		i_stream_unref(&input);
	}

	const char test_data_1[] =
		"this is some data\n"
		"written like this\n"
		"to attempt and induce\n"
		"errors or flaws\n";

#undef TEST_CASE
#define TEST_CASE(a) test_istream_create_data((a), sizeof(a))
	/* multiline tests */
	struct istream *is = TEST_CASE("\n\n\n\n\n\n");
	size_t i;
	for(i = 0; i < 6; i++)
		test_assert_strcmp_idx(i_stream_read_next_line(is), "", i);
	test_assert(is->stream_errno == 0);
	i_stream_unref(&is);

	is = TEST_CASE(
		"simple\r\n"
		"multiline\n"
		"test with\0"
		"some exciting\n"
		"things\r\n\0");
	test_assert_strcmp_idx(i_stream_read_next_line(is), "simple", 0);
	test_assert_strcmp_idx(i_stream_read_next_line(is), "multiline", 1);
	test_assert_strcmp_idx(i_stream_read_next_line(is), "test with", 2);
	test_assert_strcmp_idx(i_stream_read_next_line(is), "things", 3);
	test_assert_strcmp_idx(i_stream_read_next_line(is), NULL, 4);
	test_assert(is->stream_errno == 0);
	i_stream_unref(&is);

	is = TEST_CASE(
		"NUL\0"
		"test\n");
	test_assert_strcmp_idx(i_stream_read_next_line(is), "NUL", 0);
	test_assert_strcmp_idx(i_stream_read_next_line(is),  NULL, 1);
	test_assert(is->stream_errno == 0);
	i_stream_unref(&is);

	is = TEST_CASE(test_data_1);
	size_t n = 0;
	const char *const *lines = t_strsplit(test_data_1, "\n");
	for(i = 0; i < sizeof(test_data_1); i++) {
		test_istream_set_size(is, i);
		const char *line = i_stream_read_next_line(is);
		if (line != NULL) {
			test_assert_strcmp_idx(lines[n], line, n);
			n++;
		}
	}
	test_assert(n == 4);
	test_assert(is->stream_errno == 0);
	i_stream_unref(&is);

	const char test_data_2[] =
		"this is some data\n"
		"written like this\n"
		"to attempt and induce\n"
		"errors or flaws";

	is = TEST_CASE(test_data_2);
	lines = t_strsplit(test_data_2, "\n");
	i_stream_set_return_partial_line(is, TRUE);
	n = 0;

	for(i = 0; i < sizeof(test_data_1); i++) {
		test_istream_set_size(is, i);
		const char *line = i_stream_read_next_line(is);
		if (line != NULL) {
			test_assert_strcmp_idx(lines[n], line, n);
			n++;
		}
	}
	test_assert(n == 4);
	test_assert(is->stream_errno == 0);
	i_stream_unref(&is);

	const char test_data_3[] =
		"this is some data\r\n"
		"written like this\r\n"
		"to attempt and induce\r\n"
		"errors or flaws\r\n";


	struct istream *is_1 = TEST_CASE(test_data_3);
	is = i_stream_create_crlf(is_1);
	i_stream_unref(&is_1);

	lines = t_strsplit_spaces(test_data_3, "\r\n");
	n = 0;

	for(i = 0; i < sizeof(test_data_3); i++) {
		test_istream_set_size(is, i);
		const char *line = i_stream_read_next_line(is);
		if (line != NULL) {
			test_assert_strcmp_idx(lines[n], line, n);
			n++;
		}
	}
	test_assert(n == 4);
	test_assert(is->stream_errno == 0);
	i_stream_unref(&is);

	test_end();
}

void test_istream(void)
{
	test_istream_children();
	test_istream_next_line();
	test_istream_read_next_line();
}
