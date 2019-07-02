#ifndef EVENT_LOG_H
#define EVENT_LOG_H

struct event_filter;

#include "lib-event.h"

struct event_log_params {
	enum log_type log_type;
	const char *source_filename;
	unsigned int source_linenum;

	/* Base event used as a reference for base_* parameters (see below) */
	struct event *base_event;

	/* Append the event message to base_str_out in addition to emitting the
	   event as normal. The message appended to the string buffer includes
	   prefixes and message callback modifications by parent events up until
	   the base_event. The event is otherwise sent as normal with the full
	   prefixes and all modifications up to the root event (unless
	   no_send=TRUE). This is primarily useful to mimic (part of) event
	   logging in parallel logs that are visible to users. */
	string_t *base_str_out;

	/* Prefix inserted at the base_event for the sent log message. */
	const char *base_send_prefix;
	/* Prefix inserted at the base_event for the log message appended to the
	   string buffer. */
	const char *base_str_prefix;

	/* Don't actually send the event; only append to the provided string
	   buffer (base_str_out must not be NULL). */
	bool no_send:1;
};

void e_error(struct event *event,
	     const char *source_filename, unsigned int source_linenum,
	     const char *fmt, ...) ATTR_FORMAT(4, 5);
#define e_error(_event, ...) STMT_START { \
	struct event *_tmp_event = (_event); \
	if (event_want_level(_tmp_event, LOG_TYPE_ERROR)) \
		e_error(_tmp_event, __FILE__, __LINE__, __VA_ARGS__); \
	else \
		event_send_abort(_tmp_event); \
	} STMT_END
void e_warning(struct event *event,
	       const char *source_filename, unsigned int source_linenum,
	       const char *fmt, ...) ATTR_FORMAT(4, 5);
#define e_warning(_event, ...) STMT_START { \
	struct event *_tmp_event = (_event); \
	 if (event_want_level(_tmp_event, LOG_TYPE_WARNING)) \
		e_warning(_tmp_event, __FILE__, __LINE__, __VA_ARGS__); \
	else \
		event_send_abort(_tmp_event); \
	} STMT_END
void e_info(struct event *event,
	    const char *source_filename, unsigned int source_linenum,
	    const char *fmt, ...) ATTR_FORMAT(4, 5);
#define e_info(_event, ...) STMT_START { \
	struct event *_tmp_event = (_event); \
	if (event_want_level(_tmp_event, LOG_TYPE_INFO)) \
		e_info(_tmp_event, __FILE__, __LINE__, __VA_ARGS__); \
	else \
		event_send_abort(_tmp_event); \
	} STMT_END
void e_debug(struct event *event,
	     const char *source_filename, unsigned int source_linenum,
	     const char *fmt, ...) ATTR_FORMAT(4, 5);
#define e_debug(_event, ...) STMT_START { \
	struct event *_tmp_event = (_event); \
	if (event_want_debug(_tmp_event)) \
		e_debug(_tmp_event, __FILE__, __LINE__, __VA_ARGS__); \
	else \
		event_send_abort(_tmp_event); \
	} STMT_END

void e_log(struct event *event, enum log_type level,
	   const char *source_filename, unsigned int source_linenum,
	   const char *fmt, ...) ATTR_FORMAT(5, 6);
#define e_log(_event, level, ...) STMT_START { \
	struct event *_tmp_event = (_event); \
	if (event_want_level(_tmp_event, level)) \
		e_log(_tmp_event, level, __FILE__, __LINE__, __VA_ARGS__); \
	else \
		event_send_abort(_tmp_event); \
	} STMT_END

/* Returns TRUE if debug event should be sent (either logged or sent to
   stats). */
bool event_want_log_level(struct event *event, enum log_type level,
			  const char *source_filename,
			  unsigned int source_linenum);
#define event_want_log_level(_event, level) event_want_log_level((_event), (level), __FILE__, __LINE__)
#define event_want_debug_log(_event) event_want_log_level((_event), LOG_TYPE_DEBUG)

bool event_want_level(struct event *event, enum log_type level,
		      const char *source_filename,
		      unsigned int source_linenum);
#define event_want_level(_event, level) event_want_level((_event), (level), __FILE__, __LINE__)
#define event_want_debug(_event) event_want_level((_event), LOG_TYPE_DEBUG)

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

   Note that event_set_forced_debug(event, FALSE) is a no-op. To disable
   forced-debug, use event_unset_forced_debug(event). */
struct event *event_set_forced_debug(struct event *event, bool force);
/* Set the forced-debug to FALSE */
struct event *event_unset_forced_debug(struct event *event);
/* Set the global filter to logging debug events. */
void event_set_global_debug_log_filter(struct event_filter *filter);
/* Return the current global debug log event filter. */
struct event_filter *event_get_global_debug_log_filter(void);
/* Unset global debug log filter, if one exists. */
void event_unset_global_debug_log_filter(void);

/* Set the global filter to sending debug events. The debug events are also
   sent if they match the global debug log filter. */
void event_set_global_debug_send_filter(struct event_filter *filter);
/* Return the current global debug send event filter. */
struct event_filter *event_get_global_debug_send_filter(void);
/* Unset global debug send filter, if one exists. */
void event_unset_global_debug_send_filter(void);

/* Set/replace the global core filter, which abort()s on matching events. */
void event_set_global_core_log_filter(struct event_filter *filter);
/* Return the current global core filter. */
struct event_filter *event_get_global_core_log_filter(void);
/* Unset the global core filter, if one exists. */
void event_unset_global_core_log_filter(void);

#endif
