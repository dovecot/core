/* Copyright (c) 2020 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "lib-signals.h"
#include "time-util.h"
#include "cpu-limit.h"

#include <sys/time.h>
#include <sys/resource.h>

static struct cpu_limit *volatile cpu_limit = NULL;

struct cpu_limit {
	struct cpu_limit *parent;

	struct timeval initial_usage;
	struct rlimit old_limit, limit;

	void (*callback)(void *context);
	void *context;
};

static void
cpu_limit_handler(const siginfo_t *si ATTR_UNUSED, void *context ATTR_UNUSED)
{
	struct cpu_limit *climit = cpu_limit;

	while (climit != NULL) {
		if (climit->callback != NULL)
			climit->callback(climit->context);
		climit->callback = NULL;
		climit->context = NULL;

		if (climit->parent == NULL ||
		    climit->limit.rlim_cur < climit->parent->limit.rlim_cur)
			break;
		climit = climit->parent;
	}
}

#undef cpu_limit_init
struct cpu_limit *
cpu_limit_init(unsigned int cpu_limit_sec,
	       void (*limit_callback)(void *context), void *context)
{
	struct cpu_limit *climit;
	struct rusage rusage;

	i_assert(cpu_limit_sec > 0);

	climit = i_new(struct cpu_limit, 1);
	climit->parent = cpu_limit;
	climit->callback = limit_callback;
	climit->context = context;

	/* Query current limit */
	if (climit->parent == NULL) {
		if (getrlimit(RLIMIT_CPU, &climit->old_limit) < 0)
			i_fatal("getrlimit() failed: %m");
	} else {
		climit->old_limit = climit->parent->limit;
	}

	/* Query cpu usage so far */
	if (getrusage(RUSAGE_SELF, &rusage) < 0)
		i_fatal("getrusage() failed: %m");
	climit->initial_usage = rusage.ru_utime;
	timeval_add(&climit->initial_usage, &rusage.ru_stime);

	climit->limit = climit->old_limit;
	/* rlimit is in seconds. Truncate initial_usage to seconds for the
	   initial sanity check. */
	climit->limit.rlim_cur = climit->initial_usage.tv_sec;

	if (climit->limit.rlim_max != RLIM_INFINITY &&
	    climit->limit.rlim_cur > climit->limit.rlim_max) {
		i_fatal("CPU resource limit already exceeded (%ld > %ld)",
			(long)climit->limit.rlim_cur,
			(long)climit->limit.rlim_max);
	}
	climit->limit.rlim_cur += cpu_limit_sec;
	/* Add extra 1 second to the limit to try to avoid the limit from
	   triggering too early (although it still can trigger a few ms too
	   early). */
	climit->limit.rlim_cur++;

	if (climit->parent == NULL) {
		lib_signals_set_handler(SIGXCPU, LIBSIG_FLAG_RESTART,
					cpu_limit_handler, climit);
	} else {
		if (climit->limit.rlim_cur > climit->parent->limit.rlim_cur)
			climit->limit.rlim_cur = climit->parent->limit.rlim_cur;
	}

	if (climit->limit.rlim_max != RLIM_INFINITY &&
	    climit->limit.rlim_cur > climit->limit.rlim_max)
		climit->limit.rlim_cur = climit->limit.rlim_max;

	if (setrlimit(RLIMIT_CPU, &climit->limit) < 0)
		i_fatal("setrlimit() failed: %m");

	cpu_limit = climit;
	if (climit->parent != NULL && climit->callback != NULL &&
	    climit->parent->callback == NULL) {
		/* Resolve race condition: parent hit limit before we fully
		   initialized. */
		raise(SIGXCPU);
	}

	return climit;
}

unsigned int cpu_limit_get_usage_msecs(struct cpu_limit *climit)
{
	struct rusage rusage;
	struct timeval cpu_usage;
	int usage_diff;

	/* Query cpu usage so far */
	if (getrusage(RUSAGE_SELF, &rusage) < 0)
		i_fatal("getrusage() failed: %m");
	cpu_usage = rusage.ru_utime;
	timeval_add(&cpu_usage, &rusage.ru_stime);

	usage_diff = timeval_diff_msecs(&cpu_usage, &climit->initial_usage);
	i_assert(usage_diff >= 0);

	return (unsigned int)usage_diff;
}

void cpu_limit_deinit(struct cpu_limit **_climit)
{
	struct cpu_limit *climit = *_climit;

	*_climit = NULL;
	if (climit == NULL)
		return;

	cpu_limit = climit->parent;
	if (setrlimit(RLIMIT_CPU, &climit->old_limit) < 0)
		i_fatal("setrlimit() failed: %m");

	if (climit->parent == NULL)
		lib_signals_unset_handler(SIGXCPU, cpu_limit_handler, climit);

	i_free(climit);
}
