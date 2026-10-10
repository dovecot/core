/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "time-util.h"
#include "rate-limit.h"

void rate_limit_init(struct rate_limit *limit_r,
		     const struct rate_limit_settings *set)
{
	i_assert(set->interval_msecs > 0);
	i_assert(set->burst > 0);
	i_assert(set->burst <= UINT_MAX / set->interval_msecs);

	i_zero(limit_r);
	limit_r->set = *set;
}

unsigned int rate_limit_get_delay_msecs(const struct rate_limit *limit)
{
	const struct rate_limit_settings *set = &limit->set;
	long long diff_usecs;

	/* The event is allowed once there is at least one event's worth of
	   space left in the burst, i.e. when refill_time is at most
	   (burst-1)*interval in the future. */
	diff_usecs = timeval_diff_usecs(&limit->refill_time, &ioloop_timeval) -
		(long long)(set->burst - 1) *
		(long long)set->interval_msecs * 1000;
	if (diff_usecs <= 0)
		return 0;
	/* rate_limit_add() never moves refill_time more than one interval
	   past this point, so a longer delay means that the clock has moved
	   backwards. */
	if (diff_usecs >= (long long)set->interval_msecs * 1000)
		return set->interval_msecs;
	return (diff_usecs + 999) / 1000;
}

void rate_limit_add(struct rate_limit *limit)
{
	const struct rate_limit_settings *set = &limit->set;
	struct timeval max_refill_time;

	if (timeval_cmp(&limit->refill_time, &ioloop_timeval) < 0)
		limit->refill_time = ioloop_timeval;
	timeval_add_msecs(&limit->refill_time, set->interval_msecs);

	/* Don't let refill_time grow past the full burst. This can happen if
	   the event was added without waiting for the delay, or if the clock
	   moved backwards. */
	max_refill_time = ioloop_timeval;
	timeval_add_msecs(&max_refill_time, set->burst * set->interval_msecs);
	if (timeval_cmp(&limit->refill_time, &max_refill_time) > 0)
		limit->refill_time = max_refill_time;
}
