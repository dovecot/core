/* Copyright (c) 2009-2018 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "net.h"
#include "str.h"
#include "safe-mkstemp.h"
#include "randgen.h"
#include "istream.h"
#include "ostream.h"

#include <fcntl.h>
#include <unistd.h>

#define MAX_BUFSIZE 256

static void test_ostream_file_random_once(void)
{
	struct ostream *output;
	string_t *path = t_str_new(128);
	char buf[MAX_BUFSIZE*4], buf2[MAX_BUFSIZE*4], randbuf[MAX_BUFSIZE];
	unsigned int i, offset, size;
	ssize_t ret;
	int fd;

	memset(buf, 0, sizeof(buf));
	fd = safe_mkstemp(path, 0600, (uid_t)-1, (gid_t)-1);
	if (fd == -1)
		i_fatal("safe_mkstemp(%s) failed: %m", str_c(path));
	i_unlink(str_c(path));
	output = o_stream_create_fd(fd, MAX_BUFSIZE);
	o_stream_cork(output);

	size = i_rand_minmax(1, MAX_BUFSIZE);
	random_fill(randbuf, size);
	memcpy(buf, randbuf, size);
	test_assert(o_stream_send(output, buf, size) > 0);

	for (i = 0; i < 10; i++) {
		offset = i_rand_limit(MAX_BUFSIZE * 3);
		size = i_rand_minmax(1, MAX_BUFSIZE);
		random_fill(randbuf, size);
		memcpy(buf + offset, randbuf, size);
		test_assert(o_stream_pwrite(output, randbuf, size, offset) == 0);
		if (i_rand_limit(10) == 0)
			test_assert(o_stream_flush(output) > 0);
	}

	o_stream_uncork(output);
	test_assert(o_stream_finish(output) > 0);
	ret = pread(fd, buf2, sizeof(buf2), 0);
	if (ret < 0)
		i_fatal("pread() failed: %m");
	else {
		i_assert(ret > 0);
		test_assert(memcmp(buf, buf2, ret) == 0);
	}
	o_stream_unref(&output);
	i_close_fd(&fd);
}

static void test_ostream_file_random(void)
{
	unsigned int i;

	test_begin("ostream pwrite random");
	for (i = 0; i < 100; i++) T_BEGIN {
		test_ostream_file_random_once();
	} T_END;
	test_end();
}

static void test_ostream_file_send_istream_file(void)
{
	struct istream *input, *input2;
	struct ostream *output;
	char buf[10];
	int fd;

	test_begin("ostream file send istream file");

	/* temp file istream */
	fd = open(".temp.istream", O_RDWR | O_CREAT | O_TRUNC, 0600);
	if (fd == -1)
		i_fatal("creat(.temp.istream) failed: %m");
	test_assert(write(fd, "1234567890", 10) == 10);
	test_assert(lseek(fd, 0, SEEK_SET) == 0);
	input = i_stream_create_fd_autoclose(&fd, 1024);

	/* temp file ostream */
	fd = open(".temp.ostream", O_RDWR | O_CREAT | O_TRUNC, 0600);
	if (fd == -1)
		i_fatal("creat(.temp.ostream) failed: %m");
	output = o_stream_create_fd(fd, 0);

	/* test that writing works between two files */
	i_stream_seek(input, 3);
	input2 = i_stream_create_limit(input, 4);
	test_assert(o_stream_send_istream(output, input2) == OSTREAM_SEND_ISTREAM_RESULT_FINISHED);
	test_assert(output->offset == 4);
	test_assert(pread(fd, buf, sizeof(buf), 0) == 4 &&
		    memcmp(buf, "4567", 4) == 0);
	i_stream_unref(&input2);

	/* test that writing works within the same file */
	i_stream_destroy(&input);

	input = i_stream_create_fd(fd, 1024);
	/* forwards: 4567 -> 4677 */
	o_stream_seek(output, 1);
	i_stream_seek(input, 2);
	input2 = i_stream_create_limit(input, 2);
	test_assert(o_stream_send_istream(output, input2) == OSTREAM_SEND_ISTREAM_RESULT_FINISHED);
	test_assert(output->offset == 3);
	test_assert(pread(fd, buf, sizeof(buf), 0) == 4 &&
		    memcmp(buf, "4677", 4) == 0);
	i_stream_destroy(&input2);
	i_stream_destroy(&input);

	/* backwards: 1234 -> 11234 */
	memcpy(buf, "1234", 4);
	test_assert(pwrite(fd, buf, 4, 0) == 4);
	input = i_stream_create_fd(fd, 1024);
	o_stream_seek(output, 1);
	test_assert(o_stream_send_istream(output, input) == OSTREAM_SEND_ISTREAM_RESULT_FINISHED);
	test_assert(output->offset == 5);
	test_assert(pread(fd, buf, sizeof(buf), 0) == 5 &&
		    memcmp(buf, "11234", 5) == 0);
	i_stream_destroy(&input);

	o_stream_destroy(&output);
	i_close_fd(&fd);

	i_unlink(".temp.istream");
	i_unlink(".temp.ostream");
	test_end();
}

static void test_ostream_file_send_istream_sendfile(void)
{
	struct istream *input, *input2;
	struct ostream *output;
	char buf[10];
	int fd, sock_fd[2];

	test_begin("ostream file send istream sendfile()");

	/* temp file istream */
	fd = open(".temp.istream", O_RDWR | O_CREAT | O_TRUNC, 0600);
	if (fd == -1)
		i_fatal("creat(.temp.istream) failed: %m");
	test_assert(write(fd, "abcdefghij", 10) == 10);
	test_assert(lseek(fd, 0, SEEK_SET) == 0);
	input = i_stream_create_fd_autoclose(&fd, 1024);

	/* temp socket ostream */
	i_assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sock_fd) == 0);
	output = o_stream_create_fd_autoclose(sock_fd, 0);

	/* test that sendfile() works */
	i_stream_seek(input, 3);
	input2 = i_stream_create_limit(input, 4);
	test_assert(o_stream_send_istream(output, input2) == OSTREAM_SEND_ISTREAM_RESULT_FINISHED);
	test_assert(output->offset == 4);
	test_assert(read(sock_fd[1], buf, sizeof(buf)) == 4 &&
		    memcmp(buf, "defg", 4) == 0);
	i_stream_unref(&input2);

	/* test reading past EOF */
	i_stream_seek(input, 0);
	input2 = i_stream_create_limit(input, 20);
	test_assert(o_stream_send_istream(output, input2) == OSTREAM_SEND_ISTREAM_RESULT_FINISHED);
	test_assert(input2->v_offset == 10);
	test_assert(output->offset == 14);
	i_stream_unref(&input2);

	i_stream_unref(&input);
	o_stream_destroy(&output);
	i_close_fd(&sock_fd[1]);

	i_unlink(".temp.istream");
	test_end();
}

void test_ostream_file(void)
{
	test_ostream_file_random();
	test_ostream_file_send_istream_file();
	test_ostream_file_send_istream_sendfile();
}
