/* Copyright (c) 2007-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream-internal.h"
#include "test-common.h"

#include <stdio.h>
#include <stdlib.h>

#define OUT_NAME_ALIGN 70

static char *test_prefix;
static bool test_success;
static unsigned int failure_count;
static unsigned int total_count;

struct test_istream {
	struct istream_private istream;
	unsigned int skip_diff;
	size_t max_pos, max_buffer_size;
	bool allow_eof;
};

static ssize_t test_read(struct istream_private *stream)
{
	struct test_istream *tstream = (struct test_istream *)stream;
	unsigned int new_skip_diff;
	ssize_t ret;

	i_assert(stream->skip <= stream->pos);

	if (stream->pos - stream->skip >= tstream->max_buffer_size)
		return -2;

	if (tstream->max_pos < stream->pos) {
		/* we seeked past the end of file. */
		ret = 0;
	} else {
		/* move around the buffer */
		new_skip_diff = rand() % 128;
		stream->buffer = (stream->buffer + tstream->skip_diff) -
			new_skip_diff;
		stream->skip = (stream->skip - tstream->skip_diff) +
			new_skip_diff;
		stream->pos = (stream->pos - tstream->skip_diff) +
			new_skip_diff;
		tstream->max_pos = (tstream->max_pos - tstream->skip_diff) +
			new_skip_diff;
		tstream->skip_diff = new_skip_diff;

		ret = tstream->max_pos - stream->pos;
		stream->pos = tstream->max_pos;
	}

	if (ret > 0)
		return ret;
	else if (!tstream->allow_eof ||
		 stream->pos - tstream->skip_diff < (uoff_t)stream->statbuf.st_size)
		return 0;
	else {
		stream->istream.eof = TRUE;
		return -1;
	}
}

static void test_seek(struct istream_private *stream, uoff_t v_offset,
		      bool mark ATTR_UNUSED)
{
	struct test_istream *tstream = (struct test_istream *)stream;

	stream->istream.v_offset = v_offset;
	stream->skip = v_offset + tstream->skip_diff;
	stream->pos = stream->skip;
}

struct istream *test_istream_create_data(const void *data, size_t size)
{
	struct test_istream *tstream;

	tstream = i_new(struct test_istream, 1);
	tstream->istream.buffer = data;

	tstream->istream.read = test_read;
	tstream->istream.seek = test_seek;

	tstream->istream.istream.blocking = FALSE;
	tstream->istream.istream.seekable = TRUE;
	(void)i_stream_create(&tstream->istream, NULL, -1);
	tstream->istream.statbuf.st_size = tstream->max_pos = size;
	tstream->allow_eof = TRUE;
	tstream->max_buffer_size = (size_t)-1;
	return &tstream->istream.istream;
}

struct istream *test_istream_create(const char *data)
{
	return test_istream_create_data(data, strlen(data));
}

void test_istream_set_allow_eof(struct istream *input, bool allow)
{
	struct test_istream *tstream =
		(struct test_istream *)input->real_stream;

	tstream->allow_eof = allow;
}

void test_istream_set_max_buffer_size(struct istream *input, size_t size)
{
	struct test_istream *tstream =
		(struct test_istream *)input->real_stream;

	tstream->max_buffer_size = size;
}

void test_istream_set_size(struct istream *input, uoff_t size)
{
	struct test_istream *tstream =
		(struct test_istream *)input->real_stream;

	if (size > (uoff_t)tstream->istream.statbuf.st_size)
		size = (uoff_t)tstream->istream.statbuf.st_size;
	tstream->max_pos = size + tstream->skip_diff;
}

void test_begin(const char *name)
{
	i_assert(test_prefix == NULL);
	test_prefix = i_strdup(name);
	test_success = TRUE;
}

void test_assert_failed(const char *code, const char *file, unsigned int line)
{
	printf("%s:%u: Assert failed: %s\n", file, line, code);
	test_success = FALSE;
}

void test_end(void)
{
	i_assert(test_prefix != NULL);

	test_out("", test_success);
	i_free_and_null(test_prefix);
	test_success = FALSE;
}

void test_out(const char *name, bool success)
{
	test_out_reason(name, success, NULL);
}

void test_out_reason(const char *name, bool success, const char *reason)
{
	int i = 0;

	if (test_prefix != NULL) {
		fputs(test_prefix, stdout);
		i += strlen(test_prefix);
		if (*name != '\0') {
			putchar(':');
			i++;
		}
		putchar(' ');
		i++;
	}
	if (*name != '\0') {
		fputs(name, stdout);
		putchar(' ');
		i += strlen(name) + 1;
	}
	for (; i < OUT_NAME_ALIGN; i++)
		putchar('.');
	fputs(" : ", stdout);
	if (success)
		fputs("ok", stdout);
	else {
		fputs("FAILED", stdout);
		test_success = FALSE;
		failure_count++;
	}
	if (reason != NULL && *reason != '\0')
		printf(": %s", reason);
	putchar('\n');
	total_count++;
}

static void
test_error_handler(const struct failure_context *ctx,
		   const char *format, va_list args)
{
	default_error_handler(ctx, format, args);
#ifdef DEBUG
	if (ctx->type == LOG_TYPE_WARNING &&
	    strstr(format, "Growing") != NULL) {
		/* ignore "Growing memory pool" and "Growing data stack"
		   warnings */
		return;
	}
#endif
	test_success = FALSE;
}

void test_init(void)
{
	test_prefix = NULL;
	failure_count = 0;
	total_count = 0;

	lib_init();
	i_set_error_handler(test_error_handler);
}

int test_deinit(void)
{
	i_assert(test_prefix == NULL);
	printf("%u / %u tests failed\n", failure_count, total_count);
	lib_deinit();
	return failure_count == 0 ? 0 : 1;
}

void test_run_funcs(void (*test_functions[])(void))
{
	unsigned int i;

	for (i = 0; test_functions[i] != NULL; i++) {
		T_BEGIN {
			test_functions[i]();
		} T_END;
	}
}

int test_run(void (*test_functions[])(void))
{
	test_init();
	test_run_funcs(test_functions);
	return test_deinit();
}
