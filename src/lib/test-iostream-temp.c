/* Copyright (c) 2016 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "istream.h"
#include "ostream.h"
#include "iostream-temp.h"

#include <unistd.h>
#include <fcntl.h>

static void test_iostream_temp_create_sized_memory(void)
{
	struct ostream *output;

	test_begin("iostream_temp_create_sized() memory");
	output = iostream_temp_create_sized(".intentional-nonexistent-error/", 0, "test", 4);
	test_assert(o_stream_send(output, "123", 3) == 3);
	test_assert(output->offset == 3);
	test_assert(o_stream_send(output, "4", 1) == 1);
	test_assert(output->offset == 4);
	test_assert(o_stream_get_fd(output) == -1);

	/* now we'll try to switch to writing to a file, but it'll fail */
	test_expect_error_string("safe_mkstemp");
	test_assert(o_stream_send(output, "5", 1) == 1);
	test_expect_no_more_errors();

	test_assert(o_stream_get_fd(output) == -1);
	o_stream_destroy(&output);
	test_end();
}

static void test_iostream_temp_create_sized_disk(void)
{
	struct ostream *output;

	test_begin("iostream_temp_create_sized() disk");
	output = iostream_temp_create_sized(".", 0, "test", 4);
	test_assert(o_stream_send(output, "123", 3) == 3);
	test_assert(output->offset == 3);
	test_assert(o_stream_send(output, "4", 1) == 1);
	test_assert(output->offset == 4);
	test_assert(o_stream_get_fd(output) == -1);
	test_assert(o_stream_send(output, "5", 1) == 1);
	test_assert(output->offset == 5);
	test_assert(o_stream_get_fd(output) != -1);
	o_stream_destroy(&output);
	test_end();
}

static void test_iostream_temp_istream(void)
{
	struct istream *input, *input2, *temp_input;
	struct ostream *output;
	int fd;

	test_begin("iostream_temp istream");

	fd = open(".temp.istream", O_RDWR | O_CREAT | O_TRUNC, 0600);
	if (fd == -1)
		i_fatal("create(.temp.istream) failed: %m");
	test_assert(write(fd, "foobar", 6) == 6);
	test_assert(lseek(fd, 0, SEEK_SET) == 0);

	input = i_stream_create_fd_autoclose(&fd, 1024);
	/* a working fd-dup */
	output = iostream_temp_create_sized(".nonexistent/",
		IOSTREAM_TEMP_FLAG_TRY_FD_DUP, "test", 1);
	test_assert(o_stream_send_istream(output, input) == OSTREAM_SEND_ISTREAM_RESULT_FINISHED);
	test_assert(output->offset == 6);
	temp_input = iostream_temp_finish(&output, 128);
	test_assert(i_stream_read(temp_input) == 6);
	i_stream_destroy(&temp_input);

	/* non-working fd-dup: write data before sending istream */
	i_stream_seek(input, 0);
	output = iostream_temp_create_sized(".intentional-nonexistent-error/",
		IOSTREAM_TEMP_FLAG_TRY_FD_DUP, "test", 4);
	test_assert(o_stream_send(output, "1234", 4) == 4);
	test_assert(output->offset == 4);
	test_expect_error_string("safe_mkstemp");
	test_assert(o_stream_send_istream(output, input) == OSTREAM_SEND_ISTREAM_RESULT_FINISHED);
	test_assert(output->offset == 10);
	test_expect_no_more_errors();
	o_stream_destroy(&output);

	/* non-working fd-dup: write data after sending istream */
	i_stream_seek(input, 0);
	output = iostream_temp_create_sized(".intentional-nonexistent-error/",
		IOSTREAM_TEMP_FLAG_TRY_FD_DUP, "test", 4);
	test_assert(o_stream_send_istream(output, input) == OSTREAM_SEND_ISTREAM_RESULT_FINISHED);
	test_assert(output->offset == 6);
	test_expect_error_string("safe_mkstemp");
	test_assert(o_stream_send(output, "1", 1) == 1);
	test_assert(output->offset == 7);
	test_expect_no_more_errors();
	o_stream_destroy(&output);

	/* non-working fd-dup: send two istreams */
	i_stream_seek(input, 0);
	input2 = i_stream_create_limit(input, (uoff_t)-1);
	output = iostream_temp_create_sized(".intentional-nonexistent-error/",
		IOSTREAM_TEMP_FLAG_TRY_FD_DUP, "test", 4);
	test_assert(o_stream_send_istream(output, input) == OSTREAM_SEND_ISTREAM_RESULT_FINISHED);
	test_assert(output->offset == 6);
	test_expect_error_string("safe_mkstemp");
	test_assert(o_stream_send_istream(output, input2) == OSTREAM_SEND_ISTREAM_RESULT_FINISHED);
	test_assert(output->offset == 12);
	test_expect_no_more_errors();
	o_stream_destroy(&output);
	i_stream_unref(&input2);

	i_stream_destroy(&input);

	i_unlink(".temp.istream");
	test_end();
}

void test_iostream_temp(void)
{
	test_iostream_temp_create_sized_memory();
	test_iostream_temp_create_sized_disk();
	test_iostream_temp_istream();
}
