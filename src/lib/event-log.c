/* Copyright (c) 2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "lib-event-private.h"

#undef e_error
void e_error(struct event *event,
	     const char *source_filename, unsigned int source_linenum,
	     const char *fmt, ...)
{
	struct event_log_params params = {
		.log_type = LOG_TYPE_ERROR,
		.source_filename = source_filename,
		.source_linenum = source_linenum,
	};
	va_list args;

	va_start(args, fmt);
	event_logv(event, &params, fmt, args);
	va_end(args);
}

#undef e_warning
void e_warning(struct event *event,
	       const char *source_filename, unsigned int source_linenum,
	       const char *fmt, ...)
{
	struct event_log_params params = {
		.log_type = LOG_TYPE_WARNING,
		.source_filename = source_filename,
		.source_linenum = source_linenum,
	};
	va_list args;

	va_start(args, fmt);
	event_logv(event, &params, fmt, args);
	va_end(args);
}

#undef e_info
void e_info(struct event *event,
	    const char *source_filename, unsigned int source_linenum,
	    const char *fmt, ...)
{
	struct event_log_params params = {
		.log_type = LOG_TYPE_INFO,
		.source_filename = source_filename,
		.source_linenum = source_linenum,
	};
	va_list args;

	va_start(args, fmt);
	event_logv(event, &params, fmt, args);
	va_end(args);
}

#undef e_debug
void e_debug(struct event *event,
	     const char *source_filename, unsigned int source_linenum,
	     const char *fmt, ...)
{
	struct event_log_params params = {
		.log_type = LOG_TYPE_DEBUG,
		.source_filename = source_filename,
		.source_linenum = source_linenum,
	};
	va_list args;

	va_start(args, fmt);
	event_logv(event, &params, fmt, args);
	va_end(args);
}

static bool event_get_log_prefix(struct event *event, string_t *log_prefix)
{
	bool ret = FALSE;

	if (event->parent != NULL && !event->log_prefix_replace) {
		if (event_get_log_prefix(event->parent, log_prefix))
			ret = TRUE;
	}
	if (event->log_prefix != NULL) {
		str_append(log_prefix, event->log_prefix);
		ret = TRUE;
	}
	return ret;
}

void event_log(struct event *event, const struct event_log_params *params,
	       const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	event_logv(event, params, fmt, args);
	va_end(args);
}

static bool event_want_debug(struct event *event)
{
	return event->forced_debug;
}

static void ATTR_FORMAT(3, 0)
event_logv_type(struct event *event, enum log_type log_type,
		const char *fmt, va_list args)
{
	if (log_type == LOG_TYPE_DEBUG && !event_want_debug(event)) {
		event_send_abort(event);
		return;
	}

	const char *log_prefix = NULL;
	string_t *log_prefix_str = t_str_new(64);
	if (event_get_log_prefix(event, log_prefix_str)) {
		/* event overrides the log prefix (even if it's "") */
		log_prefix = str_c(log_prefix_str);
	}

	struct failure_context ctx = {
		.log_prefix = log_prefix,
		.type = log_type,
	};

	int old_errno = errno;
	event_send(event, &ctx, fmt, args);
	errno = old_errno;
}

void event_logv(struct event *event, const struct event_log_params *params,
		const char *fmt, va_list args)
{
	const char *orig_source_filename = event->source_filename;
	unsigned int orig_source_linenum = event->source_linenum;

	if (params->source_filename != NULL) {
		event_set_source(event, params->source_filename,
				 params->source_linenum, TRUE);
	}

	event_ref(event);
	event_logv_type(event, params->log_type, fmt, args);
	event_set_source(event, orig_source_filename,
			 orig_source_linenum, TRUE);
	event_unref(&event);
}

struct event *event_set_forced_debug(struct event *event, bool force)
{
	event->forced_debug = force;
	return event;
}
