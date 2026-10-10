#ifndef RATE_LIMIT_H
#define RATE_LIMIT_H

#include <sys/time.h> /* for struct timeval */

/* Rate limiter that allows a burst of events to happen immediately, after
   which events are allowed only once per interval. This is the Generic Cell
   Rate Algorithm (GCRA), which is equivalent to a token bucket that holds
   burst tokens and is refilled with one token per interval.

   ioloop_timeval is used as the current time, so the returned delays can be
   used directly for ioloop timeouts. Dovecot processes don't let it move
   backwards (mail processes sleep until the time has caught up, or die if
   the jump is too large), but the limiter doesn't rely on that: after a
   backwards jump the next event is delayed at most one interval, which
   resyncs the state. After a forwards jump the full burst simply becomes
   available, so the limiter only ever becomes more permissive. */

struct rate_limit_settings {
	/* Allow one event per this many milliseconds after the burst has
	   been used up. */
	unsigned int interval_msecs;
	/* Number of events allowed immediately after the rate limit has been
	   idle long enough. Must be at least 1. */
	unsigned int burst;
};

struct rate_limit {
	struct rate_limit_settings set;
	/* Time when the full burst becomes available again. Each event moves
	   this forward by interval_msecs. */
	struct timeval refill_time;
};

/* Initialize the rate limit with the full burst available. */
void rate_limit_init(struct rate_limit *limit_r,
		     const struct rate_limit_settings *set);
/* Returns how many milliseconds the next event must still wait. Returns 0
   if the event can be done immediately. */
unsigned int rate_limit_get_delay_msecs(const struct rate_limit *limit);
/* Count an event that is done now. */
void rate_limit_add(struct rate_limit *limit);

#endif
