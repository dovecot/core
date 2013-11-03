/* Copyright (c) 2001-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "env-util.h"
#include "hostpid.h"
#include "ipwd.h"
#include "process-title.h"

#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>

static ARRAY(lib_atexit_callback_t *) atexit_callbacks = ARRAY_INIT;

size_t nearest_power(size_t num)
{
	size_t n = 1;

	i_assert(num <= ((size_t)1 << (CHAR_BIT*sizeof(size_t) - 1)));

	while (n < num) n <<= 1;
	return n;
}

int close_keep_errno(int *fd)
{
	int ret, old_errno = errno;

	i_assert(*fd != -1);

	ret = close(*fd);
	*fd = -1;
	errno = old_errno;
	return ret;
}

void lib_atexit(lib_atexit_callback_t *callback)
{
	lib_atexit_callback_t *const *callbacks;
	unsigned int i, count;

	if (!array_is_created(&atexit_callbacks))
		i_array_init(&atexit_callbacks, 8);
	else {
		/* skip if it's already added */
		callbacks = array_get(&atexit_callbacks, &count);
		for (i = count; i > 0; i--) {
			if (callbacks[i-1] == callback)
				return;
		}
	}
	array_append(&atexit_callbacks, &callback, 1);
}

void lib_atexit_run(void)
{
	lib_atexit_callback_t *const *cbp;

	if (array_is_created(&atexit_callbacks)) {
		array_foreach(&atexit_callbacks, cbp)
			(**cbp)();
		array_free(&atexit_callbacks);
	}
}

void lib_init(void)
{
	struct timeval tv;

	/* standard way to get rand() return different values. */
	if (gettimeofday(&tv, NULL) < 0)
		i_fatal("gettimeofday(): %m");
	srand((unsigned int) (tv.tv_sec ^ tv.tv_usec ^ getpid()));

	data_stack_init();
	hostpid_init();
}

void lib_deinit(void)
{
	lib_atexit_run();
	ipwd_deinit();
	hostpid_deinit();
	data_stack_deinit();
	env_deinit();
	failures_deinit();
	process_title_deinit();
}
