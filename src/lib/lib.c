/* Copyright (c) 2001-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "dovecot-version.h"
#include "array.h"
#include "event-filter.h"
#include "env-util.h"
#include "hostpid.h"
#include "ipwd.h"
#include "process-title.h"
#include "restrict-access.h"
#include "var-expand-private.h"
#include "randgen.h"

#include <fcntl.h>
#include <unistd.h>
#include <sys/time.h>

/* Mainly for including the full version information in core dumps.
   NOTE: Don't set this const - otherwise it won't end up in core dumps. */
char dovecot_build_info[] = DOVECOT_BUILD_INFO;

static bool lib_initialized = FALSE;
int dev_null_fd = -1;

struct atexit_callback {
	int priority;
	lib_atexit_callback_t *callback;
};

static ARRAY(struct atexit_callback) atexit_callbacks = ARRAY_INIT;

#undef i_unlink
int i_unlink(const char *path, const char *source_fname,
	     unsigned int source_linenum)
{
	if (unlink(path) < 0) {
		i_error("unlink(%s) failed: %m (in %s:%u)",
			path, source_fname, source_linenum);
		return -1;
	}
	return 0;
}

#undef i_unlink_if_exists
int i_unlink_if_exists(const char *path, const char *source_fname,
		       unsigned int source_linenum)
{
	if (unlink(path) == 0)
		return 1;
	else if (errno == ENOENT)
		return 0;
	else {
		i_error("unlink(%s) failed: %m (in %s:%u)",
			path, source_fname, source_linenum);
		return -1;
	}
}

void i_getopt_reset(void)
{
#ifdef __GLIBC__
	/* a) for subcommands allow -options anywhere in command line
	   b) this is actually required for the reset to work (glibc bug?) */
	optind = 0;
#else
	optind = 1;
#endif
}

void lib_atexit(lib_atexit_callback_t *callback)
{
	lib_atexit_priority(callback, 0);
}

void lib_atexit_priority(lib_atexit_callback_t *callback, int priority)
{
	struct atexit_callback *cb;
	const struct atexit_callback *callbacks;
	unsigned int i, count;

	if (!array_is_created(&atexit_callbacks))
		i_array_init(&atexit_callbacks, 8);
	else {
		/* skip if it's already added */
		callbacks = array_get(&atexit_callbacks, &count);
		for (i = count; i > 0; i--) {
			if (callbacks[i-1].callback == callback) {
				i_assert(callbacks[i-1].priority == priority);
				return;
			}
		}
	}
	cb = array_append_space(&atexit_callbacks);
	cb->priority = priority;
	cb->callback = callback;
}

static int atexit_callback_priority_cmp(const struct atexit_callback *cb1,
					const struct atexit_callback *cb2)
{
	return cb1->priority - cb2->priority;
}

void lib_atexit_run(void)
{
	const struct atexit_callback *cb;

	if (array_is_created(&atexit_callbacks)) {
		array_sort(&atexit_callbacks, atexit_callback_priority_cmp);
		array_foreach(&atexit_callbacks, cb)
			(*cb->callback)();
		array_free(&atexit_callbacks);
	}
}

static void lib_open_non_stdio_dev_null(void)
{
	dev_null_fd = open("/dev/null", O_WRONLY);
	if (dev_null_fd == -1)
		i_fatal("open(/dev/null) failed: %m");
	/* Make sure stdin, stdout and stderr fds exist. We especially rely on
	   stderr being available and a lot of code doesn't like fd being 0.
	   We'll open /dev/null as write-only also for stdin, since if any
	   reads are attempted from it we'll want them to fail. */
	while (dev_null_fd < STDERR_FILENO) {
		dev_null_fd = dup(dev_null_fd);
		if (dev_null_fd == -1)
			i_fatal("dup(/dev/null) failed: %m");
	}
	/* close the actual /dev/null fd on exec*(), but keep it in stdio fds */
	fd_close_on_exec(dev_null_fd, TRUE);
}

void lib_init(void)
{
	i_assert(!lib_initialized);
	random_init();
	data_stack_init();
	hostpid_init();
	lib_open_non_stdio_dev_null();
	lib_event_init();
	event_filter_init();
	var_expand_extensions_init();

	lib_initialized = TRUE;
}

bool lib_is_initialized(void)
{
	return lib_initialized;
}

void lib_deinit(void)
{
	i_assert(lib_initialized);
	lib_initialized = FALSE;
	lib_atexit_run();
	ipwd_deinit();
	hostpid_deinit();
	var_expand_extensions_deinit();
	event_filter_deinit();
	lib_event_deinit();
	restrict_access_deinit();
	i_close_fd(&dev_null_fd);
	data_stack_deinit();
	env_deinit();
	failures_deinit();
	process_title_deinit();
	random_deinit();
}
