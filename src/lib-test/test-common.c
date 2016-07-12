/* Copyright (c) 2007-2016 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream-private.h"
#include "test-common.h"

#include <stdio.h>

#include <setjmp.h> /* for fatal tests */

/* To test the firing of i_assert, we need non-local jumps, i.e. setjmp */
static volatile bool expecting_fatal = FALSE;
static jmp_buf fatal_jmpbuf;

#define OUT_NAME_ALIGN 70

static char *test_prefix;
static bool test_success;
static unsigned int failure_count;
static unsigned int total_count;
static unsigned int expected_errors;
static char *expected_error_str;

struct test_istream {
	struct istream_private istream;
	const void *orig_buffer;
	unsigned int skip_diff;
	size_t max_pos;
	bool allow_eof;
};

static ssize_t test_read(struct istream_private *stream)
{
	struct test_istream *tstream = (struct test_istream *)stream;
	unsigned int new_skip_diff;
	size_t cur_max;
	ssize_t ret;

	i_assert(stream->skip <= stream->pos);

	if (stream->pos - stream->skip >= tstream->istream.max_buffer_size) {
		i_assert(stream->skip != stream->pos);
		return -2;
	}

	if (tstream->max_pos < stream->pos) {
		/* we seeked past the end of file. */
		ret = 0;
	} else {
		/* copy data to a buffer in somewhat random place. this could
		   help catch bugs. */
		new_skip_diff = rand() % 128;
		stream->skip = (stream->skip - tstream->skip_diff) +
			new_skip_diff;
		stream->pos = (stream->pos - tstream->skip_diff) +
			new_skip_diff;
		tstream->max_pos = (tstream->max_pos - tstream->skip_diff) +
			new_skip_diff;
		tstream->skip_diff = new_skip_diff;

		cur_max = tstream->max_pos;
		if (stream->max_buffer_size < (size_t)-1 - stream->skip &&
		    cur_max > stream->skip + stream->max_buffer_size)
			cur_max = stream->skip + stream->max_buffer_size;

		/* use exactly correct buffer size so valgrind can catch
		   read overflows */
		if (stream->buffer_size != cur_max && cur_max > 0) {
			stream->w_buffer = i_realloc(stream->w_buffer,
						     stream->buffer_size,
						     cur_max);
			stream->buffer = stream->w_buffer;
			stream->buffer_size = cur_max;
		}
		memcpy(stream->w_buffer + new_skip_diff, tstream->orig_buffer,
		       cur_max - new_skip_diff);

		ret = cur_max - stream->pos;
		stream->pos = cur_max;
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
	tstream->orig_buffer = data;

	tstream->istream.read = test_read;
	tstream->istream.seek = test_seek;

	tstream->istream.istream.blocking = FALSE;
	tstream->istream.istream.seekable = TRUE;
	i_stream_create(&tstream->istream, NULL, -1);
	tstream->istream.statbuf.st_size = tstream->max_pos = size;
	tstream->allow_eof = TRUE;
	tstream->istream.max_buffer_size = (size_t)-1;
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

	tstream->istream.max_buffer_size = size;
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
	test_success = TRUE;
	if (!expecting_fatal)
		i_assert(test_prefix == NULL);
	else
		test_assert((test_success = (test_prefix == NULL)));
	test_prefix = i_strdup(name);
}

bool test_has_failed(void)
{
	return !test_success;
}

void test_assert_failed(const char *code, const char *file, unsigned int line)
{
	printf("%s:%u: Assert failed: %s\n", file, line, code);
	fflush(stdout);
	test_success = FALSE;
}

void test_assert_failed_idx(const char *code, const char *file, unsigned int line, long long i)
{
	printf("%s:%u: Assert(#%lld) failed: %s\n", file, line, i, code);
	fflush(stdout);
	test_success = FALSE;
}

void test_assert_failed_strcmp(const char *code, const char *file, unsigned int line,
				const char * src, const char * dst)
{
	printf("%s: Assert(#%u) failed: %s\n", file, line, code);
	printf("        \"%s\" != \"%s\"\n", src, dst);
	fflush(stdout);
	test_success = FALSE;
}

static void
test_dump_rand_state(void)
{
	static int seen_count = -1;
	int count = rand_get_seed_count();
	if (count == seen_count)
		return;
	seen_count = count;
	if (count > 0)
		printf("test: random seed #%i was %u\n", 
		       rand_get_seed_count(),
		       rand_get_last_seed());
	else
		printf("test: random seed unknown\n");
}

void test_end(void)
{
	if (!expecting_fatal)
		i_assert(test_prefix != NULL);
	else
		test_assert(test_prefix != NULL);

	test_out("", test_success);
	if (!test_success)
		test_dump_rand_state();
	i_free_and_null(test_prefix);
	test_success = FALSE;
}

void test_out(const char *name, bool success)
{
	test_out_reason(name, success, NULL);
}

void test_out_quiet(const char *name, bool success)
{
	if (success) {
		total_count++;
		return;
	}
	test_out(name, success);
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
	fflush(stdout);
	total_count++;
}

void
test_expect_error_string(const char *substr)
{
	i_assert(expected_errors == 0);
	expected_errors = 1;
	expected_error_str = i_strdup(substr);
}
void
test_expect_errors(unsigned int expected)
{
	i_assert(expected_errors == 0);
	expected_errors = expected;
}
void
test_expect_no_more_errors(void)
{
	test_assert(expected_errors == 0 && expected_error_str == NULL);
	i_free_and_null(expected_error_str);
	expected_errors = 0;
}

static void ATTR_FORMAT(2, 0)
test_error_handler(const struct failure_context *ctx,
		   const char *format, va_list args)
{
	bool suppress = FALSE;

	if (expected_errors > 0) {
		if (expected_error_str != NULL) {
			/* test_assert() will reset test_success if need be. */
			suppress = strstr(format, expected_error_str) != NULL;
			test_assert(suppress == TRUE);
			i_free_and_null(expected_error_str);
		}
		expected_errors--;
	} else {
		test_success = FALSE;
	}

	if (!suppress) {
		test_dump_rand_state();
		default_error_handler(ctx, format, args);
	}
}

static void ATTR_FORMAT(2, 0) ATTR_NORETURN
test_fatal_handler(const struct failure_context *ctx,
		   const char *format, va_list args)
{
	/* Prevent recursion, we can't handle our own errors */
	i_set_fatal_handler(default_fatal_handler);
	i_assert(expecting_fatal); /* if not at the right time, bail */
	i_set_fatal_handler(test_fatal_handler);
	longjmp(fatal_jmpbuf, 1);
	/* we simply can't get here - will the compiler complain? */
	default_fatal_handler(ctx, format, args);
}

static void test_init(void)
{
	test_prefix = NULL;
	failure_count = 0;
	total_count = 0;

	lib_init();
	i_set_error_handler(test_error_handler);
	/* Don't set fatal handler until actually needed for fatal testing */
}

static int test_deinit(void)
{
	i_assert(test_prefix == NULL);
	printf("%u / %u tests failed\n", failure_count, total_count);
	lib_deinit();
	return failure_count == 0 ? 0 : 1;
}

static void test_run_funcs(void (*test_functions[])(void))
{
	unsigned int i;

	for (i = 0; test_functions[i] != NULL; i++) {
		T_BEGIN {
			test_functions[i]();
		} T_END;
	}
}
static void test_run_named_funcs(struct named_test tests[], const char *match)
{
	unsigned int i;

	for (i = 0; tests[i].func != NULL; i++) {
		if (strstr(tests[i].name, match) != NULL) T_BEGIN {
			tests[i].func();
		} T_END;
	}
}

static void run_one_fatal(enum fatal_test_state (*fatal_function)(int))
{
	static int index = 0;
	for (;;) {
		volatile int jumped = setjmp(fatal_jmpbuf);
		if (jumped == 0) {
			/* normal flow */
			expecting_fatal = TRUE;
			enum fatal_test_state ret = fatal_function(index);
			expecting_fatal = FALSE;
			if (ret == FATAL_TEST_FINISHED) {
				/* ran out of tests - good */
				index = 0;
				break;
			} else if (ret == FATAL_TEST_FAILURE) {
				/* failed to fire assert - bad, but can continue */
				test_success = FALSE;
				i_error("Desired assert failed to fire at step %i", index);
				index++;
			} else { /* FATAL_TEST_ABORT or other value */
				test_success = FALSE;
				test_end();
				index = 0;
				break;
			}
		} else {
			/* assert fired, continue with next test */
			index++;
		}
	}
}
static void test_run_fatals(enum fatal_test_state (*fatal_functions[])(int index))
{
	unsigned int i;

	for (i = 0; fatal_functions[i] != NULL; i++) {
		T_BEGIN {
			run_one_fatal(fatal_functions[i]);
		} T_END;
	}
}
static void test_run_named_fatals(const struct named_fatal fatals[], const char *match)
{
	unsigned int i;

	for (i = 0; fatals[i].func != NULL; i++) {
		if (strstr(fatals[i].name, match) != NULL) T_BEGIN {
			run_one_fatal(fatals[i].func);
		} T_END;
	}
}

int test_run(void (*test_functions[])(void))
{
	test_init();
	test_run_funcs(test_functions);
	return test_deinit();
}
int test_run_named(struct named_test tests[], const char *match)
{
	test_init();
	test_run_named_funcs(tests, match);
	return test_deinit();
}
int test_run_with_fatals(void (*test_functions[])(void),
			 enum fatal_test_state (*fatal_functions[])(int))
{
	test_init();
	test_run_funcs(test_functions);
	i_set_fatal_handler(test_fatal_handler);
	test_run_fatals(fatal_functions);
	return test_deinit();
}
int test_run_named_with_fatals(const char *match, struct named_test tests[],
			       struct named_fatal fatals[])
{
	test_init();
	test_run_named_funcs(tests, match);
	i_set_fatal_handler(test_fatal_handler);
	test_run_named_fatals(fatals, match);
	return test_deinit();
}
