#ifndef EVENT_LOG_H
#define EVENT_LOG_H

#include "lib-event.h"

struct event_log_params {
	enum log_type log_type;
	const char *source_filename;
	unsigned int source_linenum;
};

void e_error(struct event *event,
	     const char *source_filename, unsigned int source_linenum,
	     const char *fmt, ...) ATTR_FORMAT(4, 5);
#define e_error(event, ...) \
	e_error(event, __FILE__, __LINE__, __VA_ARGS__)
void e_warning(struct event *event,
	       const char *source_filename, unsigned int source_linenum,
	       const char *fmt, ...) ATTR_FORMAT(4, 5);
#define e_warning(event, ...) \
	e_warning(event, __FILE__, __LINE__, __VA_ARGS__)
void e_info(struct event *event,
	    const char *source_filename, unsigned int source_linenum,
	    const char *fmt, ...) ATTR_FORMAT(4, 5);
#define e_info(event, ...) \
	e_info(event, __FILE__, __LINE__, __VA_ARGS__)
void e_debug(struct event *event,
	     const char *source_filename, unsigned int source_linenum,
	     const char *fmt, ...) ATTR_FORMAT(4, 5);
#define e_debug(event, ...) \
	e_debug(event, __FILE__, __LINE__, __VA_ARGS__)

void event_log(struct event *event, const struct event_log_params *params,
	       const char *fmt, ...)
	ATTR_FORMAT(3, 4);
void event_logv(struct event *event, const struct event_log_params *params,
		const char *fmt, va_list args)
	ATTR_FORMAT(3, 0);

/* If debugging is forced, the global debug log filter is ignored. Changing
   this applies only to this event and any child event that is created
   afterwards. It doesn't apply to existing child events (mainly for
   performance reasons).

   Note that it's always recommended to use e.g.:
     if (set->debug) event_set_forced_debug(event, TRUE); // good
   instead of
     event_set_forced_debug(event, set->debug); // bad
   This is because the event may already have had debugging enabled via the
   parent event. Forcing it to FALSE is most likely not wanted. */
struct event *event_set_forced_debug(struct event *event, bool force);

#endif
