#ifndef LOG_THROTTLE_H
#define LOG_THROTTLE_H

struct log_throttle_settings {
	/* Start throttling after we reach this many log events/interval. */
	unsigned int throttle_at_max_per_interval;
	/* Throttling continues until there's only this many or below
	   log events/interval. */
	unsigned int unthrottle_at_max_per_interval;
	/* Interval unit in milliseconds. The throttled-callback is also called
	   at this interval. Default (0) is 1000 milliseconds. */
	unsigned int interval_msecs;
};

typedef void
log_throttle_callback_t(unsigned int new_events_count, void *context);

struct log_throttle *
log_throttle_init(const struct log_throttle_settings *set,
		  log_throttle_callback_t *callback, void *context);
#define log_throttle_init(set, callback, context) \
	log_throttle_init(set - \
		CALLBACK_TYPECHECK(callback, void (*)(unsigned int, typeof(context))), \
		(log_throttle_callback_t *)callback, context)
void log_throttle_deinit(struct log_throttle **throttle);

/* Increase event count. Returns TRUE if the event should be logged,
   FALSE if it's throttled. ioloop_timeval is used to determine the current
   time. */
bool log_throttle_accept(struct log_throttle *throttle);

#endif
