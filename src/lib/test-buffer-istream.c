/* Copyright (c) 2020 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "istream.h"
#include "str.h"
#include "write-full.h"

#include <unistd.h>
#include <fcntl.h>

#define TEST_FILENAME ".test_buffer_append_full_file"
static void test_buffer_append_full_file(void)
{
	const char *test_string = "this is a test string\n";
	test_begin("buffer_append_full_file");
	buffer_t *result = t_buffer_create(32);
	const char *error;
	int fd = open(TEST_FILENAME, O_WRONLY|O_CREAT, 0600);
	i_assert(fd > -1);
	test_assert(write_full(fd, test_string, strlen(test_string)) == 0);
	i_close_fd(&fd);

	test_assert(buffer_append_full_file(result, TEST_FILENAME, SIZE_MAX,
					    &error) == BUFFER_APPEND_OK);
	test_assert_strcmp(str_c(result), test_string);

	/* test max_read_size */
	for (size_t max = 0; max < strlen(test_string)-1; max++) {
		buffer_set_used_size(result, 0);
		test_assert(buffer_append_full_file(result, TEST_FILENAME,
					max, &error) == BUFFER_APPEND_READ_MAX_SIZE);
		test_assert(result->used == max &&
			    memcmp(result->data, test_string, max) == 0);
	}

	fd = open(TEST_FILENAME, O_WRONLY|O_TRUNC);
	i_assert(fd > -1);
	/* write it enough many times */
	for (size_t i = 0; i < IO_BLOCK_SIZE; i += strlen(test_string)) {
		test_assert(write_full(fd, test_string, strlen(test_string)) == 0);
	}
	i_close_fd(&fd);
	buffer_set_used_size(result, 0);
	test_assert(buffer_append_full_file(result, TEST_FILENAME,
					    SIZE_MAX, &error) == BUFFER_APPEND_OK);
	for (size_t i = 0; i < result->used; i += strlen(test_string)) {
		const char *data = result->data;
		data += i;
		test_assert(memcmp(data, test_string, strlen(test_string)) == 0);
	}
	buffer_set_used_size(result, 0);
	test_assert(chmod(TEST_FILENAME, 0) == 0);
	error = NULL;
	test_assert(buffer_append_full_file(result, TEST_FILENAME, SIZE_MAX,
					    &error) == BUFFER_APPEND_READ_ERROR);
	test_assert(error != NULL && *error != '\0');
	buffer_set_used_size(result, 0);
	test_assert(chmod(TEST_FILENAME, 0700) == 0);
	/* test permission problems */
	i_unlink(TEST_FILENAME);
	test_assert(buffer_append_full_file(result, TEST_FILENAME, SIZE_MAX,
					    &error) == BUFFER_APPEND_READ_ERROR);
	test_assert_strcmp(str_c(result), "");
	test_end();
}

static void test_buffer_append_full_istream(void)
{
	int fds[2];
	const char *error;
	test_begin("buffer_append_full_istream");
	buffer_t *result = t_buffer_create(32);
	test_assert(pipe(fds) == 0);
	fd_set_nonblock(fds[0], TRUE);
	fd_set_nonblock(fds[1], TRUE);

	struct istream *is = i_stream_create_fd(fds[0], (size_t)-1);
	/* test just the READ_MORE stuff */

	test_assert(write_full(fds[1], "some data ", 10) == 0);

	test_assert(buffer_append_full_istream(result, is, SIZE_MAX, &error) ==
		    BUFFER_APPEND_READ_MORE);
	test_assert(write_full(fds[1], "final read", 10) == 0);
	i_close_fd(&fds[1]);

	test_assert(buffer_append_full_istream(result, is, SIZE_MAX, &error) ==
		    BUFFER_APPEND_OK);
	test_assert_strcmp(str_c(result), "some data final read");
	i_stream_unref(&is);
	i_close_fd(&fds[0]);

	test_end();
}

void test_buffer_append_full(void)
{
	test_buffer_append_full_file();
	test_buffer_append_full_istream();
}

