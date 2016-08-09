/* Copyright (c) 2015-2016 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "net.h"
#include "fd-set-nonblock.h"
#include "fdpass.h"
#include "istream.h"
#include "istream-unix.h"

#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

static int send_fd, send_fd2;

static void write_one(int fd)
{
	if (write(fd, "1", 1) < 0)
		i_fatal("write() failed: %m");
}

static void read_one(int fd)
{
	char buf;

	if (read(fd, &buf, 1) < 0)
		i_fatal("read() failed: m");
}

static void
test_server_read_nofd(struct istream *input, unsigned int idx)
{
	const unsigned char *data;
	size_t size;

	test_assert_idx(i_stream_read_data(input, &data, &size, 0) == 1, idx);
	i_stream_skip(input, 1);
	test_assert_idx(i_stream_unix_get_read_fd(input) == -1, idx);
}

static void
test_server_read_fd(struct istream *input, int wanted_fd, unsigned int idx)
{
	struct stat st1, st2;
	const unsigned char *data;
	size_t size;
	int recv_fd;

	test_assert_idx(i_stream_read_data(input, &data, &size, 0) == 1, idx);
	i_stream_skip(input, 1);
	test_assert_idx((recv_fd = i_stream_unix_get_read_fd(input)) != -1, idx);
	if (recv_fd != -1) {
		if (fstat(recv_fd, &st1) < 0 || fstat(wanted_fd, &st2) < 0)
			i_fatal("fstat() failed: %m");
		test_assert_idx(st1.st_ino == st2.st_ino, idx);
		i_close_fd(&recv_fd);
	}
}

static void test_istream_unix_server(int fd)
{
	struct istream *input;
	const unsigned char *data;
	size_t size;

	input = i_stream_create_unix(fd, 1024);
	/* 1) simple read */
	test_server_read_nofd(input, 1);
	write_one(fd);

	/* 2) fd was sent but we won't get it */
	test_server_read_nofd(input, 2);
	/* we still shouldn't have the fd */
	fd_set_nonblock(fd, TRUE);
	i_stream_unix_set_read_fd(input);
	test_assert(i_stream_read_data(input, &data, &size, 0) == 0);
	test_assert(i_stream_unix_get_read_fd(input) == -1);
	fd_set_nonblock(fd, FALSE);
	write_one(fd);

	/* 3) the previous fd should be lost now */
	test_server_read_nofd(input, 3);
	write_one(fd);

	/* 4) we should get the fd now */
	test_server_read_fd(input, send_fd2, 4);
	write_one(fd);

	/* 5) the previous fd shouldn't be returned anymore */
	i_stream_unix_set_read_fd(input);
	test_server_read_nofd(input, 5);
	write_one(fd);

	/* 6) with i_stream_unix_unset_read_fd() we shouldn't get fd anymore */
	i_stream_unix_unset_read_fd(input);
	test_server_read_nofd(input, 6);
	write_one(fd);

	/* 7-8) two fds were sent, but we'll get only the first one */
	i_stream_unix_set_read_fd(input);
	test_server_read_fd(input, send_fd, 7);
	test_server_read_nofd(input, 8);
	write_one(fd);

	/* 9-10) two fds were sent, and we'll get them both */
	i_stream_unix_set_read_fd(input);
	test_server_read_fd(input, send_fd, 9);
	i_stream_unix_set_read_fd(input);
	test_server_read_fd(input, send_fd2, 10);
	write_one(fd);

	i_stream_destroy(&input);
	i_close_fd(&fd);
}

static void test_istream_unix_client(int fd)
{
	/* 1) */
	write_one(fd);
	read_one(fd);

	/* 2) */
	if (fd_send(fd, send_fd, "1", 1) < 0)
		i_fatal("fd_send() failed: %m");
	read_one(fd);

	/* 3) */
	write_one(fd);
	read_one(fd);

	/* 4) */
	if (fd_send(fd, send_fd2, "1", 1) < 0)
		i_fatal("fd_send() failed: %m");
	read_one(fd);

	/* 5) */
	write_one(fd);
	read_one(fd);

	/* 6) */
	if (fd_send(fd, send_fd, "1", 1) < 0)
		i_fatal("fd_send() failed: %m");
	read_one(fd);

	/* 7-8) */
	if (fd_send(fd, send_fd, "1", 1) < 0)
		i_fatal("fd_send() failed: %m");
	if (fd_send(fd, send_fd2, "1", 1) < 0)
		i_fatal("fd_send() failed: %m");
	read_one(fd);

	/* 9-10) */
	if (fd_send(fd, send_fd, "1", 1) < 0)
		i_fatal("fd_send() failed: %m");
	if (fd_send(fd, send_fd2, "1", 1) < 0)
		i_fatal("fd_send() failed: %m");
	read_one(fd);

	i_close_fd(&fd);
}

void test_istream_unix(void)
{
	int fd[2];

	test_begin("istream unix");
	if ((send_fd = open("/dev/null", O_RDONLY)) == -1)
		i_fatal("open(/dev/null) failed: %m");
	if ((send_fd2 = open("/dev/zero", O_RDONLY)) == -1)
		i_fatal("open(/dev/zero) failed: %m");
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fd) < 0)
		i_fatal("socketpair() failed: %m");
	switch (fork()) {
	case -1:
		i_fatal("fork() failed: %m");
	case 0:
		i_close_fd(&fd[0]);
		test_istream_unix_client(fd[1]);
		test_exit(0);
	default:
		i_close_fd(&fd[1]);
		test_istream_unix_server(fd[0]);
		break;
	}
	i_close_fd(&send_fd);
	i_close_fd(&send_fd2);
	test_end();
}
