/* Copyright (c) 2016-2018 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "istream.h"
#include "ostream.h"
#include "iostream-temp.h"

#include <unistd.h>
#include <fcntl.h>
#include <sys/uio.h>

static size_t test_writev_fail_at_left = 0;

static ssize_t
test_writev_fail(int fd ATTR_UNUSED, const struct iovec *iov ATTR_UNUSED,
		 unsigned int iov_count ATTR_UNUSED)
{
	errno = EIO;
	return -1;
}

static ssize_t
test_writev_fail_at(int fd, const struct iovec *iov,
		    unsigned int iov_count)
{
	struct iovec iov_copy[iov_count];
	memcpy(iov_copy, iov, sizeof(*iov) * iov_count);

	unsigned int i;
	for (i = 0; i < iov_count; i++) {
		if (test_writev_fail_at_left < iov_copy[i].iov_len) {
			iov_copy[i].iov_len = test_writev_fail_at_left;
			test_writev_fail_at_left = 0;
			i++;
			break;
		}
		test_writev_fail_at_left -= iov_copy[i].iov_len;
	}
	if (i == 1 && iov_copy[0].iov_len == 0) {
		errno = EIO;
		return -1;
	}
	return writev(fd, iov_copy, i);
}

static const char *test_iostream_temp_finish(struct ostream *output)
{
	struct istream *input = iostream_temp_finish(&output, 128);

	(void)i_stream_read(input);
	size_t size;
	const unsigned char *data = i_stream_get_data(input, &size);
	const char *str = t_strndup(data, size);
	i_stream_destroy(&input);
	return str;
}
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
	test_assert_strcmp(test_iostream_temp_finish(output), "12345");
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
	test_assert_strcmp(test_iostream_temp_finish(output), "12345");
	test_end();
}

static void test_iostream_temp_create_sized_disk_mixed(void)
{
	struct ostream *output;

	test_begin("iostream_temp_create_sized() disk (mixed)");
	output = iostream_temp_create_sized(".", 0, "test", 2);
	test_assert(o_stream_send(output, "12", 2) == 2);
	test_assert(o_stream_get_fd(output) == -1);
	test_assert(o_stream_send(output, "3", 1) == 1);
	test_assert(o_stream_get_fd(output) != -1);
	test_assert(output->offset == 3);
	test_assert(o_stream_send(output, "45", 2) == 2);
	test_assert(o_stream_send(output, "6", 1) == 1);
	test_assert_strcmp(test_iostream_temp_finish(output), "123456");
	test_end();
}

static void test_iostream_temp_create_write_error_middle(void)
{
	struct ostream *output;

	test_begin("iostream_temp_create_sized() write error (middle)");
	/* 2 bytes before it's first flushed to disk + 2 bytes in-memory buffer
	   before more data is written to disk. */
	output = iostream_temp_create_sized(".", 0, "test", 2);

	test_assert(o_stream_send(output, "12", 2) == 2);
	test_assert(o_stream_get_fd(output) == -1);
	test_assert(o_stream_send(output, "34", 2) == 2);
	test_assert(o_stream_get_fd(output) != -1);
	test_assert(output->offset == 4);

	o_stream_temp_set_writev(output, test_writev_fail);

	test_expect_error_string("iostream-temp (temp iostream in . for test): write(.*) failed: Input/output error - moving to memory");
	test_assert(o_stream_send(output, "5", 1) == 1);
	test_expect_no_more_errors();

	test_assert(o_stream_get_fd(output) == -1);
	test_assert(output->offset == 5);

	test_assert(o_stream_send(output, "6", 1) == 1);
	test_assert_strcmp(test_iostream_temp_finish(output), "123456");

	test_end();
}

static void test_iostream_temp_create_write_error_finish(void)
{
	struct ostream *output;

	test_begin("iostream_temp_create_sized() write error (finish)");

	output = iostream_temp_create_sized(".", 0, "test", 2);

	test_assert(o_stream_send(output, "12", 2) == 2);
	test_assert(o_stream_get_fd(output) == -1);
	test_assert(o_stream_send(output, "34", 2) == 2);
	test_assert(o_stream_get_fd(output) != -1);
	test_assert(output->offset == 4);

	o_stream_temp_set_writev(output, test_writev_fail);

	test_expect_error_string("iostream-temp (temp iostream in . for test): write(.*) failed: Input/output error - moving to memory");
	test_assert_strcmp(test_iostream_temp_finish(output), "1234");
	test_expect_no_more_errors();

	test_end();
}

static void test_iostream_temp_create_write_error_mixed(void)
{
	struct ostream *output;

	test_begin("iostream_temp_create_sized() write error (mixed)");

	for (unsigned int i = 0; i < 5; i++) {
		output = iostream_temp_create_sized(".", 0, "test", 2);
		test_assert_idx(o_stream_send(output, "12", 2) == 2, i);
		test_assert_idx(o_stream_get_fd(output) == -1, i);
		test_assert_idx(o_stream_send(output, "3", 1) == 1, i);
		test_assert_idx(o_stream_get_fd(output) != -1, i);
		test_assert_idx(output->offset == 3, i);

		struct const_iovec iov[2] = {
			{ "45", 2 },
			{ "67", 2 },
		};
		test_writev_fail_at_left = i;
		o_stream_temp_set_writev(output, test_writev_fail_at);

		test_expect_error_string("iostream-temp (temp iostream in . for test): write(.*) failed: Input/output error - moving to memory");
		test_assert_idx(o_stream_sendv(output, iov, 2) == 4, i);
		test_expect_no_more_errors();

		test_assert_idx(o_stream_get_fd(output) == -1, i);
		test_assert_idx(output->offset == 7, i);
		test_assert_strcmp_idx(test_iostream_temp_finish(output), "1234567", i);
	}

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
	input2 = i_stream_create_limit(input, UOFF_T_MAX);
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
	test_iostream_temp_create_sized_disk_mixed();
	test_iostream_temp_create_write_error_middle();
	test_iostream_temp_create_write_error_finish();
	test_iostream_temp_create_write_error_mixed();
	test_iostream_temp_istream();
}
