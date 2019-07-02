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
	const struct event_log_params *params;

	string_t *log_prefix;
	const char *message;
	unsigned int type_pos;

	bool replace_prefix:1;
	bool str_out_done:1;
};

static inline void ATTR_FORMAT(2, 0)
event_get_log_message_str_out(struct event_get_log_message_context *glmctx,
			      const char *fmt, va_list args)
{
	const struct event_log_params *params = glmctx->params;
	string_t *str_out = params->base_str_out;

	/* The message is appended once in full, rather than incremental during
	   the recursion. */

	if (glmctx->str_out_done || str_out == NULL)
		return;

	/* append the current log prefix to the string buffer */
	if (params->base_str_prefix != NULL && !glmctx->replace_prefix)
		str_append(str_out, params->base_str_prefix);
	str_append_str(str_out, glmctx->log_prefix);

	if (glmctx->message != NULL) {
		/* a child event already constructed a message */
		str_append(str_out, glmctx->message);
	} else {
		va_list args_copy;

		/* construct message from format and arguments */
		VA_COPY(args_copy, args);
		str_vprintfa(str_out, fmt, args_copy);
		va_end(args_copy);
	}

	/* finished with the string buffer */
	glmctx->str_out_done = TRUE;
}

static bool ATTR_FORMAT(3, 0)
event_get_log_message(struct event *event,
		      struct event_get_log_message_context *glmctx,
		      const char *fmt, va_list args)
{
	const struct event_log_params *params = glmctx->params;
	const char *prefix = event->log_prefix;
	bool ret = FALSE;

	/* Reached the base event? */
	if (event == params->base_event) {
		/* Append the message to the provided string buffer. */
		event_get_log_message_str_out(glmctx, fmt, args);
		/* Insert the base send prefix */
		if (params->base_send_prefix != NULL) {
			str_insert(glmctx->log_prefix, 0,
				   params->base_send_prefix);
			ret = TRUE;
		}
	}

	/* Call the message amendment callback for this event if there is one.
	 */
	if (event->log_message_callback != NULL) {
		const char *in_message;

		/* construct the log message composed by children and arguments
		 */
		if (glmctx->message == NULL) {
			str_vprintfa(glmctx->log_prefix, fmt, args);
			in_message = str_c(glmctx->log_prefix);
		} else if (str_len(glmctx->log_prefix) == 0) {
			in_message = glmctx->message;
		} else {
			str_append(glmctx->log_prefix, glmctx->message);
			in_message = str_c(glmctx->log_prefix);
		}

		/* reformat the log message */
		glmctx->message = event->log_message_callback(
			event->log_message_callback_context,
			glmctx->params->log_type, in_message);

		/* continue with a cleared prefix buffer (as prefix is now part
		   of *message_r). */
		str_truncate(glmctx->log_prefix, 0);
		ret = TRUE;
	}

	if (event->log_prefix_callback != NULL) {
		prefix = event->log_prefix_callback(
			event->log_prefix_callback_context);
	}
	if (event->log_prefix_replace) {
		/* this event replaces all parent log prefixes */
		glmctx->replace_prefix = TRUE;
		glmctx->type_pos = (prefix == NULL ? 0 : strlen(prefix));
		event_get_log_message_str_out(glmctx, fmt, args);
	}
	if (prefix != NULL) {
		str_insert(glmctx->log_prefix, 0, prefix);
		ret = TRUE;
	}
	if (event->parent == NULL) {
		event_get_log_message_str_out(glmctx, fmt, args);
		if (params->base_event == NULL &&
		    params->base_send_prefix != NULL &&
		    !glmctx->replace_prefix) {
			str_insert(glmctx->log_prefix, 0,
				   params->base_send_prefix);
			ret = TRUE;
		}
	} else if (!event->log_prefix_replace &&
		   (!params->no_send || !glmctx->str_out_done)) {
		if (event_get_log_message(event->parent, glmctx, fmt, args))
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
event_logv_params(struct event *event, const struct event_log_params *params,
		  const char *fmt, va_list args)
{
	struct event_get_log_message_context glmctx;

	struct failure_context ctx = {
		.type = params->log_type,
	};
	bool abort_after_event = FALSE;
	int old_errno = errno;

	i_assert(!params->no_send || params->base_str_out != NULL);

	if (global_core_log_filter != NULL &&
	    event_filter_match_source(global_core_log_filter, event,
				      event->source_filename,
				      event->source_linenum, &ctx))
		abort_after_event = TRUE;

	i_zero(&glmctx);
	glmctx.params = params;
	glmctx.log_prefix = t_str_new(64);
	if (!event_get_log_message(event, &glmctx, fmt, args)) {
		/* keep log prefix as it is */
		if (params->base_str_out != NULL && !glmctx.str_out_done) {
			va_list args_copy;

			VA_COPY(args_copy, args);
			str_vprintfa(params->base_str_out, fmt, args_copy);
			va_end(args_copy);
		}
		if (!params->no_send)
			event_vsend(event, &ctx, fmt, args);
	} else if (params->no_send) {
		/* don't send the event */
	} else if (glmctx.replace_prefix) {
		/* event overrides the log prefix (even if it's "") */
		ctx.log_prefix = str_c(glmctx.log_prefix);
		ctx.log_prefix_type_pos = glmctx.type_pos;
		if (glmctx.message != NULL)
			event_send(event, &ctx, "%s", glmctx.message);
		else
			event_vsend(event, &ctx, fmt, args);
	} else {
		/* append to log prefix, but don't fully replace it */
		if (glmctx.message != NULL)
			str_append(glmctx.log_prefix, glmctx.message);
		else
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
	event_logv_params(event, params, fmt, args);
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
