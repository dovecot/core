/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "test-lib.h"
#include "fd-util.h"

#include <unistd.h>

static void test_fd_is_readable_now(void)
{
	int fd[2];
	char c;

	test_begin("fd_is_readable_now()");
	if (pipe(fd) < 0)
		i_fatal("pipe() failed: %m");
	test_assert(!fd_is_readable_now(fd[0]));
	test_assert(write(fd[1], "x", 1) == 1);
	test_assert(fd_is_readable_now(fd[0]));
	test_assert(read(fd[0], &c, 1) == 1);
	test_assert(!fd_is_readable_now(fd[0]));
	/* EOF */
	i_close_fd(&fd[1]);
	test_assert(fd_is_readable_now(fd[0]));
	i_close_fd(&fd[0]);
	test_end();
}

void test_fd_util(void)
{
	test_fd_is_readable_now();
}

enum fatal_test_state fatal_i_close(unsigned int stage)
{
	if (stage == 0) {
		test_begin("fatal i_close");
	} else {
		test_end();
		return FATAL_TEST_FINISHED;
	}

	int fd = 0;
	const char *fatal_string = t_strdup_printf(
		"%s: close((&fd)) @ %s:%d attempted with fd=%d",
		__func__, __FILE__, __LINE__ + 2, fd);
	test_expect_fatal_string(fatal_string);
	i_close_fd(&fd);

	/* This cannot be reached. */
	return FATAL_TEST_ABORT;
}
