/* Copyright (c) 2016-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "time-util.h"
#include "log-throttle.h"

struct log_throttle {
	struct log_throttle_settings set;
	log_throttle_callback_t *callback;
	void *context;

	struct timeval last_time;
	unsigned int last_count;

	struct timeout *to_throttled;
};

#undef log_throttle_init
struct log_throttle *
log_throttle_init(const struct log_throttle_settings *set,
		  log_throttle_callback_t *callback, void *context)
{
	struct log_throttle *throttle;

	i_assert(set->throttle_at_max_per_interval > 0);
	i_assert(set->unthrottle_at_max_per_interval > 0);

	throttle = i_new(struct log_throttle, 1);
	throttle->set = *set;
	if (throttle->set.interval_msecs == 0)
		throttle->set.interval_msecs = 1000;
	throttle->callback = callback;
	throttle->context = context;
	return throttle;
}

void log_throttle_deinit(struct log_throttle **_throttle)
{
	struct log_throttle *throttle = *_throttle;

	*_throttle = NULL;
	if (throttle->to_throttled != NULL)
		timeout_remove(&throttle->to_throttled);
	i_free(throttle);
}

static void log_throttle_callback(struct log_throttle *throttle)
{
	if (throttle->last_count > 0)
		throttle->callback(throttle->last_count, throttle->context);
	if (throttle->last_count < throttle->set.unthrottle_at_max_per_interval)
		timeout_remove(&throttle->to_throttled);
	throttle->last_count = 0;
}

bool log_throttle_accept(struct log_throttle *throttle)
{
	if (throttle->to_throttled != NULL) {
		/* unthrottling and last_count resets are done only by
		   the callback */
		throttle->last_count++;
		return FALSE;
	} else if (timeval_diff_msecs(&ioloop_timeval, &throttle->last_time) >=
				(int)throttle->set.interval_msecs) {
		throttle->last_time = ioloop_timeval;
		throttle->last_count = 1;
		return TRUE;
	} else if (++throttle->last_count <= throttle->set.throttle_at_max_per_interval) {
		return TRUE;
	} else {
		throttle->last_count = 1;
		throttle->to_throttled =
			timeout_add(throttle->set.interval_msecs,
				    log_throttle_callback, throttle);
		return FALSE;
	}
}
