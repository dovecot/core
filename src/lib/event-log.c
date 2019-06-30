/* Copyright (c) 2017-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "event-filter.h"
#include "lib-event-private.h"

static struct event_filter *global_debug_log_filter = NULL;
static struct event_filter *global_debug_send_filter = NULL;
static struct event_filter *global_core_log_filter = NULL;

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

#undef e_log
void e_log(struct event *event, enum log_type level,
	   const char *source_filename, unsigned int source_linenum,
	   const char *fmt, ...)
{
	struct event_log_params params = {
		.log_type = level,
		.source_filename = source_filename,
		.source_linenum = source_linenum,
	};
	va_list args;

	va_start(args, fmt);
	event_logv(event, &params, fmt, args);
	va_end(args);
}

struct event_get_log_message_context {
	string_t *log_prefix;
	bool replace_prefix;
	unsigned int type_pos;
};

static bool
event_get_log_message(struct event *event,
		      struct event_get_log_message_context *glmctx)
{
	const char *prefix = event->log_prefix;
	bool ret = FALSE;

	if (event->log_prefix_callback != NULL) {
		prefix = event->log_prefix_callback(
			event->log_prefix_callback_context);
	}
	if (prefix != NULL) {
		str_insert(glmctx->log_prefix, 0, prefix);
		ret = TRUE;
	}

	if (event->log_prefix_replace) {
		/* this event replaces all parent log prefixes */
		glmctx->replace_prefix = TRUE;
		glmctx->type_pos = (prefix == NULL ? 0 : strlen(prefix));
	} else if (event->parent == NULL) {
		/* append to default log prefix, don't replace it */
	} else {
		if (event_get_log_message(event->parent, glmctx))
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

#undef event_want_log_level
bool event_want_log_level(struct event *event, enum log_type level,
			  const char *source_filename,
			  unsigned int source_linenum)
{
	struct failure_context ctx = { .type = LOG_TYPE_DEBUG };

	if (event->min_log_level <= level)
		return TRUE;

	if (event->forced_debug)
		event->sending_debug_log = TRUE;

	else if (global_debug_log_filter != NULL &&
		 event_filter_match_source(global_debug_log_filter, event,
					   source_filename, source_linenum, &ctx))
		event->sending_debug_log = TRUE;
	else if (global_core_log_filter != NULL &&
		 event_filter_match_source(global_core_log_filter, event,
					   source_filename, source_linenum, &ctx))
		event->sending_debug_log = TRUE;
	else
		event->sending_debug_log = FALSE;
	return event->sending_debug_log;
}

#undef event_want_level
bool event_want_level(struct event *event, enum log_type level,
		      const char *source_filename,
		      unsigned int source_linenum)
{
	(void)event_want_log_level(event, level, source_filename, source_linenum);
	if (event->sending_debug_log)
		return TRUE;

	if (event->min_log_level <= level)
		return TRUE;

	/* see if debug send filtering matches */
	if (global_debug_send_filter != NULL) {
		struct failure_context ctx = { .type = LOG_TYPE_DEBUG };

		if (event_filter_match_source(global_debug_send_filter, event,
					      source_filename, source_linenum,
					      &ctx))
			return TRUE;
	}
	return FALSE;
}

static void ATTR_FORMAT(3, 0)
event_logv_type(struct event *event, enum log_type log_type,
		const char *fmt, va_list args)
{
	struct event_get_log_message_context glmctx;

	struct failure_context ctx = {
		.type = log_type,
	};
	bool abort_after_event = FALSE;
	int old_errno = errno;

	if (global_core_log_filter != NULL &&
	    event_filter_match_source(global_core_log_filter, event,
				      event->source_filename,
				      event->source_linenum, &ctx))
		abort_after_event = TRUE;

	i_zero(&glmctx);
	glmctx.log_prefix = t_str_new(64);
	if (!event_get_log_message(event, &glmctx)) {
		/* keep log prefix as it is */
		event_vsend(event, &ctx, fmt, args);
	} else if (glmctx.replace_prefix) {
		/* event overrides the log prefix (even if it's "") */
		ctx.log_prefix = str_c(glmctx.log_prefix);
		ctx.log_prefix_type_pos = glmctx.type_pos;
		event_vsend(event, &ctx, fmt, args);
	} else {
		/* append to log prefix, but don't fully replace it */
		str_vprintfa(glmctx.log_prefix, fmt, args);
		event_send(event, &ctx, "%s", str_c(glmctx.log_prefix));
	}
	if (abort_after_event)
		abort();
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
	if (force)
		event->forced_debug = TRUE;
	return event;
}

struct event *event_unset_forced_debug(struct event *event)
{
	event->forced_debug = FALSE;
	return event;
}

void event_set_global_debug_log_filter(struct event_filter *filter)
{
	event_unset_global_debug_log_filter();
	global_debug_log_filter = filter;
	event_filter_ref(global_debug_log_filter);
}

struct event_filter *event_get_global_debug_log_filter(void)
{
	return global_debug_log_filter;
}

void event_unset_global_debug_log_filter(void)
{
	event_filter_unref(&global_debug_log_filter);
}

void event_set_global_debug_send_filter(struct event_filter *filter)
{
	event_unset_global_debug_send_filter();
	global_debug_send_filter = filter;
	event_filter_ref(global_debug_send_filter);
}

struct event_filter *event_get_global_debug_send_filter(void)
{
	return global_debug_send_filter;
}

void event_unset_global_debug_send_filter(void)
{
	event_filter_unref(&global_debug_send_filter);
}

void event_set_global_core_log_filter(struct event_filter *filter)
{
	event_unset_global_core_log_filter();
	global_core_log_filter = filter;
	event_filter_ref(global_core_log_filter);
}

struct event_filter *event_get_global_core_log_filter(void)
{
	return global_core_log_filter;
}

void event_unset_global_core_log_filter(void)
{
	event_filter_unref(&global_core_log_filter);
}
