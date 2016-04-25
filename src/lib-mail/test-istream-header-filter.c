/* Copyright (c) 2007-2016 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "istream.h"
#include "message-header-parser.h"
#include "istream-header-filter.h"
#include "test-common.h"

static void
test_istream_run(struct istream *test_istream, struct istream *filter,
		 unsigned int input_len, const char *output)
{
	unsigned int i, output_len = strlen(output);
	const unsigned char *data;
	size_t size;

	for (i = 1; i < input_len; i++) {
		test_istream_set_size(test_istream, i);
		test_assert(i_stream_read(filter) >= 0);
	}
	test_istream_set_size(test_istream, input_len);
	test_assert(i_stream_read(filter) > 0);
	test_assert(i_stream_read(filter) == -1);

	data = i_stream_get_data(filter, &size);
	test_assert(size == output_len && memcmp(data, output, size) == 0);

	/* run again to make sure it's still correct the second time */
	i_stream_skip(filter, size);
	i_stream_seek(filter, 0);
	while (i_stream_read(filter) > 0) ;
	data = i_stream_get_data(filter, &size);
	test_assert(size == output_len && memcmp(data, output, size) == 0);
}

static void ATTR_NULL(3)
filter_callback(struct header_filter_istream *input ATTR_UNUSED,
		struct message_header_line *hdr,
		bool *matched, void *context ATTR_UNUSED)
{
	if (hdr != NULL && (hdr->name_offset == 0 ||
			    strcmp(hdr->name, "X-Drop") == 0)) {
		/* drop 1) first header, 2) X-Drop header */
		*matched = TRUE;
	}
}

static void test_istream_filter(void)
{
	static const char *exclude_headers[] = { "Subject", "To" };
	const char *input = "From: foo\nFrom: abc\nTo: bar\nSubject: plop\nX-Drop: 1\n\nhello world\n";
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
					       exclude_headers,
					       N_ELEMENTS(exclude_headers),
					       filter_callback, (void *)NULL);
	filter2 = i_stream_create_header_filter(filter,
						HEADER_FILTER_EXCLUDE |
						HEADER_FILTER_NO_CR,
						exclude_headers,
						N_ELEMENTS(exclude_headers),
						*null_header_filter_callback,
						(void *)NULL);
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

static void add_random_text(string_t *dest, unsigned int count)
{
	unsigned int i;

	for (i = 0; i < count; i++)
		str_append_c(dest, rand() % ('z'-'a'+1) + 'a');
}

static void ATTR_NULL(3)
filter2_callback(struct header_filter_istream *input ATTR_UNUSED,
		 struct message_header_line *hdr,
		 bool *matched, void *context ATTR_UNUSED)
{
	if (hdr != NULL && strcmp(hdr->name, "To") == 0)
		*matched = TRUE;
}

static void test_istream_filter_large_buffer(void)
{
	string_t *input, *output;
	struct istream *istream, *filter;
	const unsigned char *data;
	size_t size, prefix_len;
	const char *p;
	unsigned int i;

	test_begin("i_stream_create_header_filter(large buffer)");

	input = str_new(default_pool, 1024*128);
	output = str_new(default_pool, 1024*128);
	str_append(input, "From: ");
	add_random_text(input, 1024*31);
	str_append(input, "\nTo: ");
	add_random_text(input, 1024*32);
	str_append(input, "\nSubject: ");
	add_random_text(input, 1024*34);
	str_append(input, "\n\nbody\n");

	istream = test_istream_create_data(str_data(input), str_len(input));
	test_istream_set_max_buffer_size(istream, 8192);

	filter = i_stream_create_header_filter(istream,
					       HEADER_FILTER_EXCLUDE |
					       HEADER_FILTER_NO_CR,
					       NULL, 0,
					       filter2_callback,
					       (void *)NULL);

	for (i = 0; i < 2; i++) {
		for (;;) {
			ssize_t ret = i_stream_read(filter);
			i_assert(ret != 0);
			if (ret == -1)
				break;
			if (ret == -2) {
				data = i_stream_get_data(filter, &size);
				str_append_n(output, data, size);
				i_stream_skip(filter, size);
			}
		}

		data = i_stream_get_data(filter, &size);
		test_assert(size <= 8192);
		str_append_n(output, data, size);

		p = strstr(str_c(input), "To: ");
		i_assert(p != NULL);
		prefix_len = p - str_c(input);
		test_assert(strncmp(str_c(input), str_c(output), prefix_len) == 0);

		p = strchr(p, '\n');
		i_assert(p != NULL);
		test_assert(strcmp(p+1, str_c(output) + prefix_len) == 0);

		/* seek back and retry once with caching and different
		   buffer size */
		i_stream_seek(filter, 0);
		str_truncate(output, 0);
		test_istream_set_max_buffer_size(istream, 4096);
	}

	str_free(&input);
	str_free(&output);
	i_stream_unref(&filter);
	i_stream_unref(&istream);

	test_end();
}

static void
filter3_callback(struct header_filter_istream *input ATTR_UNUSED,
		 struct message_header_line *hdr,
		 bool *matched ATTR_UNUSED, string_t *dest)
{
	if (hdr != NULL)
		message_header_line_write(dest, hdr);
}

static void test_istream_callbacks(void)
{
	string_t *input, *output;
	struct istream *istream, *filter;
	unsigned int i;

	test_begin("i_stream_create_header_filter(callbacks)");

	input = str_new(default_pool, 1024*128);
	output = str_new(default_pool, 1024*128);
	str_append(input, "From: first line\n ");
	add_random_text(input, 1024*31);
	str_append(input, "\nTo: first line\n\tsecond line\n\t");
	add_random_text(input, 1024*32);
	str_append(input, "\n last line\nSubject: ");
	add_random_text(input, 1024*34);
	str_append(input, "\n");

	istream = test_istream_create_data(str_data(input), str_len(input));
	test_istream_set_max_buffer_size(istream, 8192);

	filter = i_stream_create_header_filter(istream,
					       HEADER_FILTER_EXCLUDE |
					       HEADER_FILTER_NO_CR,
					       NULL, 0,
					       filter3_callback,
					       output);

	/* callback should be called exactly once for all the header input */
	for (i = 0; i < 2; i++) {
		while (i_stream_read(filter) != -1)
			i_stream_skip(filter, i_stream_get_data_size(filter));
	}

	test_assert(strcmp(str_c(output), str_c(input)) == 0);
	str_free(&input);
	str_free(&output);
	i_stream_unref(&filter);
	i_stream_unref(&istream);

	test_end();
}

static void ATTR_NULL(3)
edit_callback(struct header_filter_istream *input,
	      struct message_header_line *hdr,
	      bool *matched, void *context ATTR_UNUSED)
{
	if (hdr != NULL && strcasecmp(hdr->name, "To") == 0) {
		/* modify To header */
		const char *new_to = "To: 123\n";
		*matched = TRUE;
		i_stream_header_filter_add(input, new_to, strlen(new_to));
	}
}

static void test_istream_edit(void)
{
	const char *input = "From: foo\nTo: bar\n\nhello world\n";
	const char *output = "From: foo\nTo: 123\n\nhello world\n";
	struct istream *istream, *filter;

	test_begin("i_stream_create_header_filter(edit)");
	istream = test_istream_create(input);
	filter = i_stream_create_header_filter(istream,
					       HEADER_FILTER_EXCLUDE |
					       HEADER_FILTER_NO_CR,
					       NULL, 0,
					       edit_callback, (void *)NULL);
	test_istream_run(istream, filter, strlen(input), output);
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
					       *null_header_filter_callback,
					       (void *)NULL);

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

static void ATTR_NULL(3)
strip_eoh_callback(struct header_filter_istream *input ATTR_UNUSED,
		   struct message_header_line *hdr,
		   bool *matched, void *context ATTR_UNUSED)
{
	if (hdr != NULL && hdr->eoh)
		*matched = FALSE;
}

static void test_istream_strip_eoh(void)
{
	const char *input = "From: foo\nTo: bar\n\nhello world\n";
	const char *output = "From: foo\nTo: bar\nhello world\n";
	struct istream *istream, *filter;

	test_begin("i_stream_create_header_filter(edit)");
	istream = test_istream_create(input);
	filter = i_stream_create_header_filter(istream,
			HEADER_FILTER_EXCLUDE | HEADER_FILTER_NO_CR, NULL, 0,
			strip_eoh_callback, (void *)NULL);
	test_istream_run(istream, filter, strlen(input), output);
	i_stream_unref(&filter);
	i_stream_unref(&istream);

	test_end();
}

int main(void)
{
	static void (*test_functions[])(void) = {
		test_istream_filter,
		test_istream_filter_large_buffer,
		test_istream_callbacks,
		test_istream_edit,
		test_istream_end_body_with_lf,
		test_istream_strip_eoh,
		NULL
	};
	return test_run(test_functions);
}
