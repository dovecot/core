/* Copyright (c) 2007-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "istream.h"
#include "message-header-parser.h"
#include "istream-header-filter.h"
#include "test-common.h"

struct run_ctx {
	header_filter_callback *callback;
	unsigned int callback_call_count;
	bool null_hdr_seen;
	bool eoh_seen;
	bool callback_called;
};

static void run_callback(struct header_filter_istream *input,
			 struct message_header_line *hdr,
			 bool *matched, struct run_ctx *ctx)
{
	i_assert(!ctx->null_hdr_seen);

	ctx->callback_call_count++;
	if (hdr == NULL)
		ctx->null_hdr_seen = TRUE;
	else {
		i_assert(!ctx->eoh_seen);
		if (hdr->eoh)
			ctx->eoh_seen = TRUE;
	}
	if (ctx->callback != NULL)
		ctx->callback(input, hdr, matched, NULL);
	ctx->callback_called = TRUE;
}

static inline void
test_istream_run_prep(struct run_ctx *run_ctx,
		      header_filter_callback *callback)
{
	i_zero(run_ctx);
	run_ctx->callback = callback;
	run_ctx->null_hdr_seen = FALSE;
	run_ctx->eoh_seen = FALSE;
	run_ctx->callback_called = FALSE;
}

static void
test_istream_run_check(struct run_ctx *run_ctx,
		       struct istream *filter,
		       const char *output,
		       enum header_filter_flags flags,
		       bool first,
		       size_t *size_r)
{
	const unsigned char *data;
	const struct stat *st;

	if (first)
		test_assert(run_ctx->null_hdr_seen);
	else
		test_assert(run_ctx->null_hdr_seen == run_ctx->callback_called);

	if (first && ((flags & HEADER_FILTER_ADD_MISSING_EOH) != 0))
		test_assert(run_ctx->eoh_seen);

	data = i_stream_get_data(filter, size_r);
	test_assert(*size_r == strlen(output) &&
		    memcmp(data, output, *size_r) == 0);

	test_assert(i_stream_stat(filter, TRUE, &st) == 0 &&
		    (uoff_t)st->st_size == *size_r);
}

static void
test_istream_run(struct istream *test_istream,
		 unsigned int input_len, const char *output,
		 enum header_filter_flags flags,
		 header_filter_callback *callback)
{
	struct run_ctx run_ctx;
	struct istream *filter;
	unsigned int i, orig_callback_call_count;
	size_t size;

	test_istream_run_prep(&run_ctx, callback);

	filter = i_stream_create_header_filter(test_istream, flags, NULL, 0,
					       run_callback, &run_ctx);

	for (i = 1; i < input_len; i++) {
		test_istream_set_size(test_istream, i);
		test_assert(i_stream_read(filter) >= 0);
	}
	test_istream_set_size(test_istream, input_len);
	test_assert(i_stream_read(filter) > 0);
	test_assert(i_stream_read(filter) == -1);

	test_istream_run_check(&run_ctx, filter, output, flags, TRUE, &size);
	orig_callback_call_count = run_ctx.callback_call_count;

	/* run again to make sure it's still correct the second time */
	test_istream_run_prep(&run_ctx, callback);

	i_stream_skip(filter, size);
	i_stream_seek(filter, 0);
	while (i_stream_read(filter) > 0) ;
	test_istream_run_check(&run_ctx, filter, output, flags, FALSE, &size);
	test_assert(run_ctx.callback_call_count == 0 ||
		    run_ctx.callback_call_count == orig_callback_call_count);

	i_stream_unref(&filter);
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
	unsigned int i;
	size_t input_len = strlen(input);
	size_t output_len = strlen(output);
	const unsigned char *data;
	const struct stat *st;
	size_t size;

	test_begin("i_stream_create_header_filter: exclude");
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

	test_assert(i_stream_stat(filter, TRUE, &st) == 0 &&
		    (uoff_t)st->st_size == size);

	i_stream_skip(filter, size);
	i_stream_seek(filter, 0);
	while (i_stream_read(filter) > 0) ;
	data = i_stream_get_data(filter, &size);
	test_assert(size == output_len && memcmp(data, output, size) == 0);
	test_assert(i_stream_stat(filter, TRUE, &st) == 0 &&
		    (uoff_t)st->st_size == size);

	i_stream_unref(&filter);
	i_stream_unref(&istream);

	test_end();
}

static void add_random_text(string_t *dest, unsigned int count)
{
	unsigned int i;

	for (i = 0; i < count; i++)
		str_append_c(dest, i_rand_minmax('a', 'z'));
}

static void ATTR_NULL(3)
filter2_callback(struct header_filter_istream *input ATTR_UNUSED,
		 struct message_header_line *hdr,
		 bool *matched, bool *null_hdr_seen)
{
	if (hdr == NULL)
		*null_hdr_seen = TRUE;
	else if (strcmp(hdr->name, "To") == 0)
		*matched = TRUE;
}

static void test_istream_filter_large_buffer(void)
{
	string_t *input, *output;
	struct istream *istream, *filter;
	const struct stat *st;
	const unsigned char *data;
	size_t size, prefix_len;
	const char *p;
	unsigned int i;
	bool null_hdr_seen = FALSE;

	test_begin("i_stream_create_header_filter: large buffer");

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
					       &null_hdr_seen);

	for (i = 0; i < 2; i++) {
		for (;;) {
			ssize_t ret = i_stream_read(filter);
			i_assert(ret != 0);
			if (ret == -1)
				break;
			if (ret == -2) {
				data = i_stream_get_data(filter, &size);
				str_append_data(output, data, size);
				i_stream_skip(filter, size);
			}
		}
		/* callbacks are called only once */
		test_assert(null_hdr_seen == (i == 0));

		data = i_stream_get_data(filter, &size);
		test_assert(size <= 8192);
		str_append_data(output, data, size);

		p = strstr(str_c(input), "To: ");
		i_assert(p != NULL);
		prefix_len = p - str_c(input);
		test_assert(strncmp(str_c(input), str_c(output), prefix_len) == 0);

		p = strchr(p, '\n');
		i_assert(p != NULL);
		test_assert(strcmp(p+1, str_c(output) + prefix_len) == 0);

		test_assert(i_stream_stat(filter, TRUE, &st) == 0 &&
			    (uoff_t)st->st_size == filter->v_offset + size);

		/* seek back and retry once with caching and different
		   buffer size */
		i_stream_seek(filter, 0);
		str_truncate(output, 0);
		test_istream_set_max_buffer_size(istream, 4096);
		null_hdr_seen = FALSE;
	}

	str_free(&input);
	str_free(&output);
	i_stream_unref(&filter);
	i_stream_unref(&istream);

	test_end();
}

static void test_istream_filter_large_buffer2(void)
{
	static const char *wanted_headers[] = { "References" };
	string_t *input, *output;
	struct istream *istream, *filter;
	const struct stat *st;
	const unsigned char *data;
	size_t size;
	unsigned int i;
	int ret;

	test_begin("i_stream_create_header_filter: large buffer2");

	input = str_new(default_pool, 1024*128);
	output = str_new(default_pool, 1024*128);
	str_append(input, "References: ");
	add_random_text(input, 1024*64);
	str_append(input, "\r\n\r\n");

	istream = test_istream_create_data(str_data(input), str_len(input));
	test_istream_set_max_buffer_size(istream, 8192);

	filter = i_stream_create_header_filter(istream,
		HEADER_FILTER_INCLUDE | HEADER_FILTER_HIDE_BODY,
		wanted_headers, N_ELEMENTS(wanted_headers),
		*null_header_filter_callback, (void *)NULL);

	for (i = 0; i < 2; i++) {
		while ((ret = i_stream_read_more(filter, &data, &size)) > 0) {
			str_append_data(output, data, size);
			i_stream_skip(filter, size);
		}
		test_assert(ret == -1);
		test_assert(filter->stream_errno == 0);

		test_assert(strcmp(str_c(input), str_c(output)) == 0);
		test_assert(i_stream_stat(filter, TRUE, &st) == 0 &&
			    (uoff_t)st->st_size == filter->v_offset + size);

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
	const struct stat *st;
	struct istream *istream, *filter;
	unsigned int i;

	test_begin("i_stream_create_header_filter: callbacks");

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

	test_assert(i_stream_stat(filter, TRUE, &st) == 0 &&
		    (uoff_t)st->st_size == str_len(output));
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
	if (hdr == NULL)
		return;
	if (hdr->eoh) {
		/* add a new header */
		const char *new_hdr = "Added: header\n\n";
		i_stream_header_filter_add(input, new_hdr, strlen(new_hdr));
		*matched = TRUE;
	} else if (strcasecmp(hdr->name, "To") == 0) {
		/* modify To header */
		const char *new_to = "To: 123\n";
		*matched = TRUE;
		i_stream_header_filter_add(input, new_to, strlen(new_to));
	}
}

static void test_istream_edit(void)
{
	const char *input = "From: foo\nTo: bar\n\nhello world\n";
	const char *output = "From: foo\nTo: 123\nAdded: header\n\nhello world\n";
	struct istream *istream;

	test_begin("i_stream_create_header_filter: edit headers");
	istream = test_istream_create(input);
	test_istream_run(istream, strlen(input), output,
			 HEADER_FILTER_EXCLUDE |
			 HEADER_FILTER_NO_CR,
			 edit_callback);
	i_stream_unref(&istream);

	test_end();
}

static void test_istream_end_body_with_lf(void)
{
	const char *input = "From: foo\n\nhello world";
	const char *output = "From: foo\n\nhello world\n";
	const struct stat *st;
	struct istream *istream, *filter;
	unsigned int i;
	size_t input_len = strlen(input);
	size_t output_len = strlen(output);
	const unsigned char *data;
	string_t *str = t_str_new(64);
	size_t size;

	test_begin("i_stream_create_header_filter: end_body_with_lf");
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
	test_assert(i_stream_stat(filter, TRUE, &st) == 0 &&
		    (uoff_t)st->st_size == filter->v_offset + size);

	i_stream_skip(filter, size);
	i_stream_seek(filter, 0);
	for (i = 1; i < input_len; i++) {
		test_istream_set_size(istream, i);
		test_assert(i_stream_read(filter) >= 0);

		data = i_stream_get_data(filter, &size);
		if (size > 0)
			str_append_data(str, data, size);
		i_stream_skip(filter, size);
	}
	test_istream_set_size(istream, input_len);
	test_assert(i_stream_read(filter) == 1);
	test_assert(i_stream_read(filter) == 1);
	test_assert(i_stream_read(filter) == -1);

	data = i_stream_get_data(filter, &size);
	str_append_data(str, data, size);
	test_assert(strcmp(str_c(str), output) == 0);

	i_stream_unref(&filter);
	i_stream_unref(&istream);

	test_end();
}

static void test_istream_add_missing_eoh(void)
{
	static const struct {
		const char *input;
		const char *output;
		unsigned int extra;
	} tests[] = {
		{ "", "\n", 0 },
		{ "From: foo", "From: foo\n\n", 1 },
		{ "From: foo\n", "From: foo\n\n", 1 },
		{ "From: foo\n\n", "From: foo\n\n", 1 },
		{ "From: foo\n\nbar", "From: foo\n\nbar", 0 },
		{ "From: foo\r\n", "From: foo\r\n\r\n", 1 },
		{ "From: foo\r\n\r\n", "From: foo\r\n\r\n", 0 },
		{ "From: foo\r\n\r\nbar", "From: foo\r\n\r\nbar", 0 }
	};
	struct istream *istream;
	unsigned int i;

	test_begin("i_stream_create_header_filter: add missing EOH");
	for (i = 0; i < N_ELEMENTS(tests); i++) {
		istream = test_istream_create(tests[i].input);
		test_istream_run(istream,
				 strlen(tests[i].input) + tests[i].extra,
				 tests[i].output,
				 HEADER_FILTER_EXCLUDE |
				 HEADER_FILTER_CRLF_PRESERVE |
				 HEADER_FILTER_ADD_MISSING_EOH,
				 *null_header_filter_callback);
		i_stream_unref(&istream);
	}
	test_end();
}

static void test_istream_add_missing_eoh_and_edit(void)
{
	const char *input = "From: foo\nTo: bar\n";
	const char *output = "From: foo\nTo: 123\nAdded: header\n\n";
	struct istream *istream;

	test_begin("i_stream_create_header_filter: add missing EOH and edit headers");
	istream = test_istream_create(input);
	test_istream_run(istream, strlen(input), output,
			 HEADER_FILTER_EXCLUDE |
			 HEADER_FILTER_ADD_MISSING_EOH |
			 HEADER_FILTER_NO_CR,
			 edit_callback);
	i_stream_unref(&istream);

	test_end();
}

static void test_istream_hide_body(void)
{
	static const struct {
		const char *input;
		const char *output;
		int extra;
	} tests[] = {
		{ "From: foo", "From: foo", 0 },
		{ "From: foo\n", "From: foo\n", 0 },
		{ "From: foo\n\n", "From: foo\n\n", 1 },
		{ "From: foo\n\nbar", "From: foo\n\n", -2 },
		{ "From: foo\r\n", "From: foo\r\n", 0 },
		{ "From: foo\r\n\r\n", "From: foo\r\n\r\n", 0 },
		{ "From: foo\r\n\r\nbar", "From: foo\r\n\r\n", -3 }
	};
	struct istream *istream;
	unsigned int i;

	test_begin("i_stream_create_header_filter: hide body");
	for (i = 0; i < N_ELEMENTS(tests); i++) {
		istream = test_istream_create(tests[i].input);
		test_istream_run(istream,
				 (int)strlen(tests[i].input) + tests[i].extra,
				 tests[i].output,
				 HEADER_FILTER_EXCLUDE |
				 HEADER_FILTER_CRLF_PRESERVE |
				 HEADER_FILTER_HIDE_BODY,
				 *null_header_filter_callback);
		i_stream_unref(&istream);
	}
	test_end();
}

static void ATTR_NULL(3)
strip_eoh_callback(struct header_filter_istream *input ATTR_UNUSED,
		   struct message_header_line *hdr,
		   bool *matched, void *context ATTR_UNUSED)
{
	if (hdr != NULL && hdr->eoh)
		*matched = TRUE;
}

static void test_istream_strip_eoh(void)
{
	const char *input = "From: foo\nTo: bar\n\nhello world\n";
	const char *output = "From: foo\nTo: bar\nhello world\n";
	struct istream *istream;

	test_begin("i_stream_create_header_filter: strip_eoh");
	istream = test_istream_create(input);
	test_istream_run(istream, strlen(input), output,
			 HEADER_FILTER_EXCLUDE | HEADER_FILTER_NO_CR,
			 strip_eoh_callback);
	i_stream_unref(&istream);

	test_end();
}

static void ATTR_NULL(3)
missing_eoh_callback(struct header_filter_istream *input ATTR_UNUSED,
		     struct message_header_line *hdr,
		     bool *matched ATTR_UNUSED, void *context ATTR_UNUSED)
{
	if (hdr == NULL) {
		const char *new_hdr = "Subject: added\n\n";
		i_stream_header_filter_add(input, new_hdr, strlen(new_hdr));
	}
}

static void test_istream_missing_eoh_callback(void)
{
	const char *input = "From: foo\nTo: bar\n";
	const char *output = "From: foo\nTo: bar\nSubject: added\n\n";
	struct istream *istream;

	test_begin("i_stream_create_header_filter: add headers when EOH is missing");
	istream = test_istream_create(input);
	test_istream_run(istream, strlen(input) + 1, output,
			 HEADER_FILTER_EXCLUDE | HEADER_FILTER_NO_CR,
			 missing_eoh_callback);
	i_stream_unref(&istream);
	test_end();
}

static void test_istream_empty_missing_eoh_callback(void)
{
	const char *input = "";
	const char *output = "Subject: added\n\n";
	struct istream *istream;

	test_begin("i_stream_create_header_filter: add headers when mail is empty");
	istream = test_istream_create(input);
	test_istream_run(istream, strlen(input)+1, output,
			 HEADER_FILTER_EXCLUDE | HEADER_FILTER_NO_CR,
			 missing_eoh_callback);
	i_stream_unref(&istream);
	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_istream_filter,
		test_istream_filter_large_buffer,
		test_istream_filter_large_buffer2,
		test_istream_callbacks,
		test_istream_edit,
		test_istream_add_missing_eoh,
		test_istream_add_missing_eoh_and_edit,
		test_istream_end_body_with_lf,
		test_istream_hide_body,
		test_istream_strip_eoh,
		test_istream_missing_eoh_callback,
		test_istream_empty_missing_eoh_callback,
		NULL
	};
	return test_run(test_functions);
}
