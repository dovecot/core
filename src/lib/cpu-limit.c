/* Copyright (c) 2020 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "lib-signals.h"
#include "time-util.h"
#include "cpu-limit.h"

#include <sys/time.h>
#include <sys/resource.h>

struct cpu_limit {
	struct cpu_limit *parent;

	enum cpu_limit_type type;
	unsigned int cpu_limit_secs;
	struct rusage initial_usage;

	bool limit_reached;
};

static struct cpu_limit *cpu_limit;
static struct rlimit orig_limit, last_set_rlimit;
static volatile sig_atomic_t xcpu_signal_counter;
static sig_atomic_t checked_signal_counter;
static unsigned int rlim_cur_adjust_secs;

static void
cpu_limit_handler(const siginfo_t *si ATTR_UNUSED, void *context ATTR_UNUSED)
{
	xcpu_signal_counter++;
}

static unsigned int
cpu_limit_get_usage_msecs_with(struct cpu_limit *climit,
			       enum cpu_limit_type type,
			       const struct rusage *rusage)
{
	struct timeval cpu_usage = { 0, 0 };
	int usage_diff;

	if ((type & CPU_LIMIT_TYPE_USER) != 0)
		timeval_add(&cpu_usage, &rusage->ru_utime);
	if ((type & CPU_LIMIT_TYPE_SYSTEM) != 0)
		timeval_add(&cpu_usage, &rusage->ru_stime);

	struct timeval initial_total = { 0, 0 };
	if ((type & CPU_LIMIT_TYPE_USER) != 0)
		timeval_add(&initial_total, &climit->initial_usage.ru_utime);
	if ((type & CPU_LIMIT_TYPE_SYSTEM) != 0)
		timeval_add(&initial_total, &climit->initial_usage.ru_stime);
	usage_diff = timeval_diff_msecs(&cpu_usage, &initial_total);
	i_assert(usage_diff >= 0);

	return (unsigned int)usage_diff;
}

unsigned int
cpu_limit_get_usage_msecs(struct cpu_limit *climit, enum cpu_limit_type type)
{
	struct rusage rusage;

	/* Query cpu usage so far */
	if (getrusage(RUSAGE_SELF, &rusage) < 0)
		i_fatal("getrusage() failed: %m");

	return cpu_limit_get_usage_msecs_with(climit, type, &rusage);
}

static bool
cpu_limit_update_recursive(struct cpu_limit *climit,
			   const struct rusage *rusage,
			   unsigned int *max_wait_secs)
{
	if (climit == NULL)
		return FALSE;
	if (cpu_limit_update_recursive(climit->parent, rusage, max_wait_secs)) {
		/* parent's limit reached */
		climit->limit_reached = TRUE;
		return TRUE;
	}
	unsigned int secs_used =
		cpu_limit_get_usage_msecs_with(climit, climit->type, rusage)/1000;
	if (secs_used >= climit->cpu_limit_secs) {
		climit->limit_reached = TRUE;
		return TRUE;
	}
	unsigned int secs_left = climit->cpu_limit_secs - secs_used;
	if (*max_wait_secs > secs_left)
		*max_wait_secs = secs_left;
	return FALSE;
}

static void cpu_limit_update_rlimit(void)
{
	struct rusage rusage;
	struct rlimit rlimit;
	unsigned int max_wait_secs = UINT_MAX;

	if (getrusage(RUSAGE_SELF, &rusage) < 0)
		i_fatal("getrusage() failed: %m");

	(void)cpu_limit_update_recursive(cpu_limit, &rusage, &max_wait_secs);
	if (max_wait_secs == UINT_MAX) {
		/* All the limits have reached now. Restore the original
		   limits. */
		rlimit = orig_limit;
	} else {
		struct timeval tv_limit = rusage.ru_utime;
		timeval_add(&tv_limit, &rusage.ru_stime);

		i_zero(&rlimit);
		/* Add +1 second to round up. */
		rlimit.rlim_cur = tv_limit.tv_sec +
			max_wait_secs + 1 + rlim_cur_adjust_secs;
		rlimit.rlim_max = orig_limit.rlim_max;
	}
	if (last_set_rlimit.rlim_cur != rlimit.rlim_cur) {
		last_set_rlimit = rlimit;
		if (setrlimit(RLIMIT_CPU, &rlimit) < 0)
			i_fatal("setrlimit() failed: %m");
	}
}

struct cpu_limit *
cpu_limit_init(unsigned int cpu_limit_secs, enum cpu_limit_type type)
{
	struct cpu_limit *climit;
	struct rusage rusage;

	i_assert(cpu_limit_secs > 0);
	i_assert(type != 0);

	climit = i_new(struct cpu_limit, 1);
	climit->parent = cpu_limit;
	climit->type = type;
	climit->cpu_limit_secs = cpu_limit_secs;

	/* Query current limit */
	if (climit->parent == NULL) {
		if (getrlimit(RLIMIT_CPU, &orig_limit) < 0)
			i_fatal("getrlimit() failed: %m");
	}

	/* Query cpu usage so far */
	if (getrusage(RUSAGE_SELF, &rusage) < 0)
		i_fatal("getrusage() failed: %m");
	climit->initial_usage = rusage;

	if (climit->parent == NULL) {
		lib_signals_set_handler(SIGXCPU, LIBSIG_FLAG_RESTART,
					cpu_limit_handler, NULL);
	}

	cpu_limit = climit;
	cpu_limit_update_rlimit();
	return climit;
}

void cpu_limit_deinit(struct cpu_limit **_climit)
{
	struct cpu_limit *climit = *_climit;

	*_climit = NULL;
	if (climit == NULL)
		return;

	i_assert(climit == cpu_limit);

	cpu_limit = climit->parent;
	cpu_limit_update_rlimit();
	if (climit->parent == NULL)
		lib_signals_unset_handler(SIGXCPU, cpu_limit_handler, NULL);
	i_free(climit);
}

bool cpu_limit_exceeded(struct cpu_limit *climit)
{
	static struct timeval tv_last = { 0, 0 };
	struct timeval tv_now;

	if (checked_signal_counter != xcpu_signal_counter) {
		i_gettimeofday(&tv_now);
		if (tv_last.tv_sec != 0 &&
		    timeval_diff_msecs(&tv_now, &tv_last) < 1000) {
			/* Additional sanity check: We're getting here more
			   rapidly than once per second. This isn't expected
			   to happen, but at least in theory it could happen
			   because rlim_cur isn't clearly calculated from just
			   the user+system CPU usage. So in case rlim_cur is
			   too low and keeps firing XCPU signal, try to
			   increase rlim_cur by 1 second. Eventually it should
			   become large enough. */
			rlim_cur_adjust_secs++;
		}

		checked_signal_counter = xcpu_signal_counter;
		cpu_limit_update_rlimit();
	}
	return climit->limit_reached;
}
