/* Copyright (c) 2019 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "fd-util.h"

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
