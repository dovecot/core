/* Copyright (c) 2007-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "istream.h"
#include "message-header-parser.h"
#include "istream-header-filter.h"
#include "test-common.h"

static void filter_callback(struct message_header_line *hdr,
			    bool *matched, void *context ATTR_UNUSED)
{
	if (hdr != NULL && hdr->name_offset == 0) {
		/* drop first header */
		*matched = TRUE;
	}
}

static void test_istream_filter(void)
{
	static const char *exclude_headers[] = { "Subject", "To", NULL };
	const char *input = "From: foo\nFrom: abc\nTo: bar\nSubject: plop\n\nhello world\n";
	const char *output = "From: abc\n\nhello world\n";
	struct istream *istream, *filter, *filter2;
	unsigned int i, input_len = strlen(input);
	unsigned int output_len = strlen(output);
	const unsigned char *data;
	size_t size;

	test_begin("i_stream_create_header_filter(exclude)");
	istream = test_istream_create(input);
	filter = i_stream_create_header_filter(istream,
					       HEADER_FILTER_EXCLUDE |
					       HEADER_FILTER_NO_CR,
					       exclude_headers, 2,
					       filter_callback, NULL);
	filter2 = i_stream_create_header_filter(filter,
						HEADER_FILTER_EXCLUDE |
						HEADER_FILTER_NO_CR,
						exclude_headers, 2,
						null_header_filter_callback, NULL);
	i_stream_unref(&filter);
	filter = filter2;

	for (i = 1; i < input_len; i++) {
		test_istream_set_size(istream, i);
		test_assert(i_stream_read(filter) >= 0);
	}
	test_istream_set_size(istream, input_len);
	test_assert(i_stream_read(filter) > 0);
	test_assert(i_stream_read(filter) == -1);

	data = i_stream_get_data(filter, &size);
	test_assert(size == output_len && memcmp(data, output, size) == 0);

	i_stream_skip(filter, size);
	i_stream_seek(filter, 0);
	while (i_stream_read(filter) > 0) ;
	data = i_stream_get_data(filter, &size);
	test_assert(size == output_len && memcmp(data, output, size) == 0);

	i_stream_unref(&filter);
	i_stream_unref(&istream);

	test_end();
}

static void test_istream_end_body_with_lf(void)
{
	const char *input = "From: foo\n\nhello world";
	const char *output = "From: foo\n\nhello world\n";
	struct istream *istream, *filter;
	unsigned int i, input_len = strlen(input);
	unsigned int output_len = strlen(output);
	const unsigned char *data;
	string_t *str = t_str_new(64);
	size_t size;

	test_begin("i_stream_create_header_filter(end_body_with_lf)");
	istream = test_istream_create(input);
	filter = i_stream_create_header_filter(istream,
					       HEADER_FILTER_EXCLUDE |
					       HEADER_FILTER_NO_CR |
					       HEADER_FILTER_END_BODY_WITH_LF,
					       NULL, 0,
					       null_header_filter_callback, NULL);

	for (i = 1; i < input_len; i++) {
		test_istream_set_size(istream, i);
		test_assert(i_stream_read(filter) >= 0);
	}
	test_istream_set_size(istream, input_len);
	test_assert(i_stream_read(filter) > 0);
	test_assert(i_stream_read(filter) > 0);
	test_assert(i_stream_read(filter) == -1);

	data = i_stream_get_data(filter, &size);
	test_assert(size == output_len && memcmp(data, output, size) == 0);

	i_stream_skip(filter, size);
	i_stream_seek(filter, 0);
	for (i = 1; i < input_len; i++) {
		test_istream_set_size(istream, i);
		test_assert(i_stream_read(filter) >= 0);

		data = i_stream_get_data(filter, &size);
		str_append_n(str, data, size);
		i_stream_skip(filter, size);
	}
	test_istream_set_size(istream, input_len);
	test_assert(i_stream_read(filter) == 1);
	test_assert(i_stream_read(filter) == 1);
	test_assert(i_stream_read(filter) == -1);

	data = i_stream_get_data(filter, &size);
	str_append_n(str, data, size);
	test_assert(strcmp(str_c(str), output) == 0);

	i_stream_unref(&filter);
	i_stream_unref(&istream);

	test_end();
}

int main(void)
{
	static void (*test_functions[])(void) = {
		test_istream_filter,
		test_istream_end_body_with_lf,
		NULL
	};
	return test_run(test_functions);
}
