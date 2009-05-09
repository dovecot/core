/* Copyright (c) 2007-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream-internal.h"
#include "test-common.h"

#include <stdio.h>

#define OUT_NAME_ALIGN 70

static char *test_prefix;
static bool test_success;
static unsigned int failure_count;
static unsigned int total_count;

static ssize_t test_read(struct istream_private *stream)
{
	if (stream->pos < (uoff_t)stream->statbuf.st_size)
		return 0;

	stream->istream.eof = TRUE;
	return -1;
}

static ssize_t test_noread(struct istream_private *stream ATTR_UNUSED)
{
	return 0;
}

struct istream *test_istream_create(const char *data)
{
	struct istream *input;
	unsigned int len = strlen(data);

	input = i_stream_create_from_data(data, len);
	input->blocking = FALSE;
	input->real_stream->statbuf.st_size = len;
	input->real_stream->read = test_read;
	return input;
}

void test_istream_set_size(struct istream *input, uoff_t size)
{
	input->real_stream->pos = size;
}

void test_istream_set_allow_eof(struct istream *input, bool allow)
{
	input->real_stream->read = allow ? test_read : test_noread;
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

static void test_init(void)
{
	test_prefix = NULL;
	failure_count = 0;
	total_count = 0;

	lib_init();
}

static int test_deinit(void)
{
	i_assert(test_prefix == NULL);
	printf("%u / %u tests failed\n", failure_count, total_count);
	return failure_count == 0 ? 0 : 1;
}

int test_run(void (*test_functions[])(void))
{
	unsigned int i;

	test_init();
	for (i = 0; test_functions[i] != NULL; i++) {
		T_BEGIN {
			test_functions[i]();
		} T_END;
	}
	return test_deinit();
}
