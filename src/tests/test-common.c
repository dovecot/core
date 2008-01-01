/* Copyright (c) 2007-2008 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream-internal.h"
#include "test-common.h"

#include <stdio.h>

#define OUT_NAME_ALIGN 30

static unsigned int failure_count;
static unsigned int total_count;

static ssize_t test_read(struct istream_private *stream)
{
	if (stream->pos < (uoff_t)stream->statbuf.st_size)
		return 0;

	stream->istream.eof = TRUE;
	return -1;
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

void test_out(const char *name, bool success)
{
	test_out_reason(name, success, NULL);
}

void test_out_reason(const char *name, bool success, const char *reason)
{
	int i;

	fputs(name, stdout);
	putchar(' ');
	for (i = strlen(name) + 1; i < OUT_NAME_ALIGN; i++)
		putchar('.');
	fputs(" : ", stdout);
	if (success)
		fputs("ok", stdout);
	else {
		fputs("FAILED", stdout);
		failure_count++;
	}
	if (reason != NULL && *reason != '\0')
		printf(": %s", reason);
	putchar('\n');
	total_count++;
}

void test_init(void)
{
	failure_count = 0;
	total_count = 0;

	lib_init();
}

int test_deinit(void)
{
	printf("%u / %u tests failed\n", failure_count, total_count);
	return failure_count == 0 ? 0 : 1;
}
