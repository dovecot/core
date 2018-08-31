/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "str.h"
#include "hostpid.h"
#include "net.h"
#include "process-title.h"
#include "lib-signals.h"
#include "backtrace-string.h"
#include "printf-format-fix.h"
#include "write-full.h"
#include "failures-private.h"

#include <unistd.h>
#include <fcntl.h>
#include <syslog.h>
#include <time.h>
#include <poll.h>

#define LOG_TYPE_FLAG_DISABLE_LOG_PREFIX 0x80

const char *failure_log_type_prefixes[LOG_TYPE_COUNT] = {
	"Debug: ",
	"Info: ",
	"Warning: ",
	"Error: ",
	"Fatal: ",
	"Panic: "
};

const char *failure_log_type_names[LOG_TYPE_COUNT] = {
	"debug", "info", "warning", "error", "fatal", "panic"
};

static int log_fd_write(int fd, const unsigned char *data, size_t len);

static void error_handler_real(const struct failure_context *ctx,
			    const char *format, va_list args);

/* Initialize working defaults */
static failure_callback_t *fatal_handler ATTR_NORETURN =
	default_fatal_handler;
static failure_callback_t *error_handler = default_error_handler;
static failure_callback_t *info_handler = default_error_handler;
static failure_callback_t *debug_handler = default_error_handler;
static void (*failure_exit_callback)(int *) = NULL;

static struct failure_context failure_ctx_debug = { .type = LOG_TYPE_DEBUG };
static struct failure_context failure_ctx_info = { .type = LOG_TYPE_INFO };
static struct failure_context failure_ctx_warning = { .type = LOG_TYPE_WARNING };
static struct failure_context failure_ctx_error = { .type = LOG_TYPE_ERROR };

static int log_fd = STDERR_FILENO, log_info_fd = STDERR_FILENO,
	   log_debug_fd = STDERR_FILENO;
static char *log_prefix = NULL;
static char *log_stamp_format = NULL, *log_stamp_format_suffix = NULL;
static bool failure_ignore_errors = FALSE, log_prefix_sent = FALSE;
static bool coredump_on_error = FALSE;
static void log_prefix_add(const struct failure_context *ctx, string_t *str);
static void i_failure_send_option(const char *key, const char *value);
static int internal_send_split(string_t *full_str, size_t prefix_len);

static string_t * ATTR_FORMAT(3, 0) default_format(const struct failure_context *ctx,
						   size_t *prefix_len_r ATTR_UNUSED,
						   const char *format,
						   va_list args)
{
	string_t *str = t_str_new(256);
	log_prefix_add(ctx, str);
	str_append(str, failure_log_type_prefixes[ctx->type]);

	/* make sure there's no %n in there and fix %m */
	str_vprintfa(str, printf_format_fix(format), args);
	return str;
}

static int default_write(enum log_type type, string_t *data, size_t prefix_len ATTR_UNUSED)
{
	int fd;

	switch (type) {
	case LOG_TYPE_DEBUG:
		fd = log_debug_fd;
		break;
	case LOG_TYPE_INFO:
		fd = log_info_fd;
		break;
	default:
		fd = log_fd;
		break;
	}
	str_append_c(data, '\n');
	return log_fd_write(fd, str_data(data), str_len(data));
}

static void default_on_handler_failure(const struct failure_context *ctx)
{
	const char *log_type = "info";
	switch (ctx->type) {
	case LOG_TYPE_DEBUG:
		log_type = "debug";
		/* fall through */
	case LOG_TYPE_INFO:
		/* we failed to log to info/debug log, try to log the
		   write error to error log - maybe that'll work. */
		i_fatal_status(FATAL_LOGWRITE, "write() failed to %s log: %m",
			       log_type);
		break;
	default:
		failure_exit(FATAL_LOGWRITE);
		break;
	}
}

static void default_post_handler(const struct failure_context *ctx)
{
	if (ctx->type == LOG_TYPE_ERROR && coredump_on_error)
		abort();
}

static string_t * ATTR_FORMAT(3, 0) syslog_format(const struct failure_context *ctx,
						  size_t *prefix_len_r ATTR_UNUSED,
						  const char *format,
						  va_list args)
{
	string_t *str = t_str_new(128);
	if (ctx->log_prefix != NULL)
		str_append(str, ctx->log_prefix);
	else if (log_prefix != NULL)
		str_append(str, log_prefix);
	if (ctx->type != LOG_TYPE_INFO)
		str_append(str, failure_log_type_prefixes[ctx->type]);
	str_vprintfa(str, format, args);
	return str;
}

static int syslog_write(enum log_type type, string_t *data, size_t prefix_len ATTR_UNUSED)
{
	int level = LOG_ERR;

	switch (type) {
	case LOG_TYPE_DEBUG:
		level = LOG_DEBUG;
		break;
	case LOG_TYPE_INFO:
		level = LOG_INFO;
		break;
	case LOG_TYPE_WARNING:
		level = LOG_WARNING;
		break;
	case LOG_TYPE_ERROR:
		level = LOG_ERR;
		break;
	case LOG_TYPE_FATAL:
	case LOG_TYPE_PANIC:
		level = LOG_CRIT;
		break;
	case LOG_TYPE_COUNT:
	case LOG_TYPE_OPTION:
		i_unreached();
	}
	syslog(level, "%s", str_c(data));
	return 0;
}

static void syslog_on_handler_failure(const struct failure_context *ctx ATTR_UNUSED)
{
	failure_exit(FATAL_LOGERROR);
}

static void syslog_post_handler(const struct failure_context *ctx ATTR_UNUSED)
{
}

static string_t * ATTR_FORMAT(3, 0) internal_format(const struct failure_context *ctx,
						    size_t *prefix_len_r,
						    const char *format,
						    va_list args)
{
	string_t *str;
	unsigned char log_type = ctx->type + 1;

	if (ctx->log_prefix != NULL) {
		log_type |= LOG_TYPE_FLAG_DISABLE_LOG_PREFIX;
	} else if (!log_prefix_sent && log_prefix != NULL) {
		log_prefix_sent = TRUE;
		i_failure_send_option("prefix", log_prefix);
	}

	str = t_str_new(128);
	str_printfa(str, "\001%c%s ", log_type, my_pid);
	if (ctx->log_prefix != NULL)
		str_append(str, ctx->log_prefix);
	*prefix_len_r = str_len(str);

	str_vprintfa(str, format, args);
	return str;
}

static int internal_write(enum log_type type ATTR_UNUSED, string_t *data, size_t prefix_len)
{
	if (str_len(data)+1 <= PIPE_BUF) {
		str_append_c(data, '\n');
		return log_fd_write(STDERR_FILENO,
				    str_data(data), str_len(data));
	}
	return internal_send_split(data, prefix_len);
}

static void internal_on_handler_failure(const struct failure_context *ctx ATTR_UNUSED)
{
	failure_exit(FATAL_LOGERROR);
}

static void internal_post_handler(const struct failure_context *ctx ATTR_UNUSED)
{
}

static struct failure_handler_vfuncs default_handler_vfuncs = {
	.write = &default_write,
	.format = &default_format,
	.on_handler_failure = &default_on_handler_failure,
	.post_handler = &default_post_handler
};

static struct failure_handler_vfuncs syslog_handler_vfuncs = {
	.write = &syslog_write,
	.format = &syslog_format,
	.on_handler_failure = &syslog_on_handler_failure,
	.post_handler = &syslog_post_handler
};

static struct failure_handler_vfuncs internal_handler_vfuncs = {
	.write = &internal_write,
	.format = &internal_format,
	.on_handler_failure = &internal_on_handler_failure,
	.post_handler = &internal_post_handler
};

struct failure_handler_config failure_handler = { .fatal_err_reset = FATAL_LOGWRITE,
						 .v = &default_handler_vfuncs };

static int common_handler(const struct failure_context *ctx,
			  const char *format, va_list args)
{
	static int recursed = 0;
	int ret;
	size_t prefix_len = 0;

	if (recursed >= 2) {
		/* we're being called from some signal handler or we ran
		   out of memory */
		return -1;
	}
	recursed++;

	T_BEGIN {
		string_t *str = failure_handler.v->format(ctx, &prefix_len, format, args);
		ret = failure_handler.v->write(ctx->type, str, prefix_len);
	} T_END;

	if (ret < 0 && failure_ignore_errors)
		ret = 0;

	recursed--;
	return ret;
}

static void error_handler_real(const struct failure_context *ctx,
			 const char *format, va_list args)
{
	if (common_handler(ctx, format, args) < 0)
		failure_handler.v->on_handler_failure(ctx);
	failure_handler.v->post_handler(ctx);
}

static void ATTR_FORMAT(2, 0)
i_internal_error_handler(const struct failure_context *ctx,
			 const char *format, va_list args);

/* kludgy .. we want to trust log_stamp_format with -Wformat-nonliteral */
static const char *
get_log_stamp_format(const char *format_arg, unsigned int timestamp_usecs)
	ATTR_FORMAT_ARG(1);

static const char *get_log_stamp_format(const char *format_arg ATTR_UNUSED,
					unsigned int timestamp_usecs)
{
	if (log_stamp_format_suffix == NULL)
		return log_stamp_format;
	return t_strdup_printf("%s%06u%s", log_stamp_format,
			       timestamp_usecs, log_stamp_format_suffix);
}

void failure_exit(int status)
{
	static bool recursed = FALSE;

	if (failure_exit_callback != NULL && !recursed) {
		recursed = TRUE;
		failure_exit_callback(&status);
	}
	exit(status);
}

static void log_prefix_add(const struct failure_context *ctx, string_t *str)
{
	const struct tm *tm = ctx->timestamp;
	char buf[256];
	struct timeval now;

	if (log_stamp_format != NULL) {
		if (tm == NULL) {
			if (gettimeofday(&now, NULL) < 0)
				i_panic("gettimeofday() failed: %m");
			tm = localtime(&now.tv_sec);
		} else {
			now.tv_usec = ctx->timestamp_usecs;
		}

		if (strftime(buf, sizeof(buf),
			     get_log_stamp_format("unused", now.tv_usec), tm) > 0)
			str_append(str, buf);
	}
	if (ctx->log_prefix != NULL)
		str_append(str, ctx->log_prefix);
	else if (log_prefix != NULL)
		str_append(str, log_prefix);
}

static void fd_wait_writable(int fd)
{
	struct pollfd pfd = {
		.fd = fd,
		.events = POLLOUT | POLLERR | POLLHUP | POLLNVAL,
	};

	/* Use poll() instead of ioloop, because we don't want to recurse back
	   to log writing in case something fails. */
	if (poll(&pfd, 1, -1) < 0 && errno != EINTR) {
		/* Unexpected error. We're already blocking on log writes,
		   so we can't log it. */
		abort();
	}
}

static int log_fd_write(int fd, const unsigned char *data, size_t len)
{
	ssize_t ret;
	unsigned int prev_signal_term_counter = signal_term_counter;
	unsigned int terminal_eintr_count = 0;
	const char *old_title = NULL;
	bool failed = FALSE, process_title_changed = FALSE;

	while (!failed &&
	       (ret = write(fd, data, len)) != (ssize_t)len) {
		if (ret > 0) {
			/* some was written, continue.. */
			data += ret;
			len -= ret;
			continue;
		}
		if (ret == 0) {
			/* out of disk space? */
			errno = ENOSPC;
			failed = TRUE;
			break;
		}
		switch (errno) {
		case EAGAIN: {
			/* Log fd is nonblocking - wait until we can write more.
			   Indicate in process title that the process is waiting
			   because it's waiting on the log.

			   Remember that the log fd is shared across processes,
			   which also means the log fd flags are shared. So if
			   one process changes the O_NONBLOCK flag for a log fd,
			   all the processes see the change. To avoid problems,
			   we'll wait using poll() instead of changing the
			   O_NONBLOCK flag. */
			if (!process_title_changed) {
				const char *title;

				process_title_changed = TRUE;
				old_title = t_strdup(process_title_get());
				if (old_title == NULL)
					title = "[blocking on log write]";
				else
					title = t_strdup_printf("%s - [blocking on log write]",
								old_title);
				process_title_set(title);
			}
			fd_wait_writable(fd);
			break;
		}
		case EINTR:
			if (prev_signal_term_counter == signal_term_counter) {
				/* non-terminal signal. ignore. */
			} else if (terminal_eintr_count++ == 0) {
				/* we'd rather not die in the middle of
				   writing to log. try again once more */
			} else {
				/* received two terminal signals.
				   someone wants us dead. */
				failed = TRUE;
				break;
			}
			break;
		default:
			failed = TRUE;
			break;
		}
		prev_signal_term_counter = signal_term_counter;
	}
	if (process_title_changed)
		process_title_set(old_title);
	return failed ? -1 : 0;
}

static void ATTR_NORETURN
default_fatal_finish(enum log_type type, int status)
{
	const char *backtrace;
	static int recursed = 0;

	recursed++;
	if ((type == LOG_TYPE_PANIC || status == FATAL_OUTOFMEM) &&
	    recursed == 1) {
		if (backtrace_get(&backtrace) == 0)
			i_error("Raw backtrace: %s", backtrace);
	}
	recursed--;

	if (type == LOG_TYPE_PANIC || getenv("CORE_ERROR") != NULL ||
	    (status == FATAL_OUTOFMEM && getenv("CORE_OUTOFMEM") != NULL))
		abort();
	else
		failure_exit(status);
}

static void ATTR_NORETURN fatal_handler_real(const struct failure_context *ctx,
			    const char *format, va_list args)
{
	int status = ctx->exit_status;
	if (common_handler(ctx, format, args) < 0 &&
	    status == FATAL_DEFAULT)
		status = failure_handler.fatal_err_reset;
	default_fatal_finish(ctx->type, status);
}

void default_fatal_handler(const struct failure_context *ctx,
			   const char *format, va_list args)
{
	failure_handler.v = &default_handler_vfuncs;
	failure_handler.fatal_err_reset = FATAL_LOGWRITE;
	fatal_handler_real(ctx, format, args);
}

void default_error_handler(const struct failure_context *ctx,
			   const char *format, va_list args)
{
	failure_handler.v = &default_handler_vfuncs;
	failure_handler.fatal_err_reset = FATAL_LOGWRITE;
	error_handler_real(ctx, format, args);
}

void i_log_type(const struct failure_context *ctx, const char *format, ...)
{
	va_list args;

	va_start(args, format);
	i_log_typev(ctx, format, args);
	va_end(args);
}

void i_log_typev(const struct failure_context *ctx, const char *format,
		 va_list args)
{
	switch (ctx->type) {
	case LOG_TYPE_DEBUG:
		debug_handler(ctx, format, args);
		break;
	case LOG_TYPE_INFO:
		info_handler(ctx, format, args);
		break;
	default:
		error_handler(ctx, format, args);
	}
}

void i_panic(const char *format, ...)
{
	struct failure_context ctx;
	va_list args;

	i_zero(&ctx);
	ctx.type = LOG_TYPE_PANIC;

	va_start(args, format);
	fatal_handler(&ctx, format, args);
	i_unreached();
	/*va_end(args);*/
}

void i_fatal(const char *format, ...)
{
	struct failure_context ctx;
	va_list args;

	i_zero(&ctx);
	ctx.type = LOG_TYPE_FATAL;
	ctx.exit_status = FATAL_DEFAULT;

	va_start(args, format);
	fatal_handler(&ctx, format, args);
	i_unreached();
	/*va_end(args);*/
}

void i_fatal_status(int status, const char *format, ...)
{
	struct failure_context ctx;
	va_list args;

	i_zero(&ctx);
	ctx.type = LOG_TYPE_FATAL;
	ctx.exit_status = status;

	va_start(args, format);
	fatal_handler(&ctx, format, args);
	i_unreached();
	/*va_end(args);*/
}

void i_error(const char *format, ...)
{
	int old_errno = errno;
	va_list args;

	va_start(args, format);
	error_handler(&failure_ctx_error, format, args);
	va_end(args);

	errno = old_errno;
}

void i_warning(const char *format, ...)
{
	int old_errno = errno;
	va_list args;

	va_start(args, format);
	error_handler(&failure_ctx_warning, format, args);
	va_end(args);

	errno = old_errno;
}

void i_info(const char *format, ...)
{
	int old_errno = errno;
	va_list args;

	va_start(args, format);
	info_handler(&failure_ctx_info, format, args);
	va_end(args);

	errno = old_errno;
}

void i_debug(const char *format, ...)
{
	int old_errno = errno;
	va_list args;

	va_start(args, format);
	debug_handler(&failure_ctx_debug, format, args);
	va_end(args);

	errno = old_errno;
}

void i_set_fatal_handler(failure_callback_t *callback ATTR_NORETURN)
{
        fatal_handler = callback;
}

void i_set_error_handler(failure_callback_t *callback)
{
	coredump_on_error = getenv("CORE_ERROR") != NULL;
	error_handler = callback;
}

void i_set_info_handler(failure_callback_t *callback)
{
	info_handler = callback;
}

void i_set_debug_handler(failure_callback_t *callback)
{
	debug_handler = callback;
}

void i_get_failure_handlers(failure_callback_t **fatal_callback_r,
			    failure_callback_t **error_callback_r,
			    failure_callback_t **info_callback_r,
			    failure_callback_t **debug_callback_r)
{
	*fatal_callback_r = fatal_handler;
	*error_callback_r = error_handler;
	*info_callback_r = info_handler;
	*debug_callback_r = debug_handler;
}

void i_syslog_fatal_handler(const struct failure_context *ctx,
			    const char *format, va_list args)
{
	failure_handler.v = &syslog_handler_vfuncs;
	failure_handler.fatal_err_reset = FATAL_LOGERROR;
	fatal_handler_real(ctx, format, args);
}

void i_syslog_error_handler(const struct failure_context *ctx,
			    const char *format, va_list args)
{
	failure_handler.v = &syslog_handler_vfuncs;
	failure_handler.fatal_err_reset = FATAL_LOGERROR;
	error_handler_real(ctx, format, args);
}

void i_set_failure_syslog(const char *ident, int options, int facility)
{
	openlog(ident, options, facility);

	i_set_fatal_handler(i_syslog_fatal_handler);
	i_set_error_handler(i_syslog_error_handler);
	i_set_info_handler(i_syslog_error_handler);
	i_set_debug_handler(i_syslog_error_handler);
}

static void open_log_file(int *fd, const char *path)
{
	const char *str;

	if (*fd != STDERR_FILENO) {
		if (close(*fd) < 0) {
			str = t_strdup_printf("close(%d) failed: %m\n", *fd);
			(void)write_full(STDERR_FILENO, str, strlen(str));
		}
	}

	if (path == NULL || strcmp(path, "/dev/stderr") == 0)
		*fd = STDERR_FILENO;
	else {
		*fd = open(path, O_CREAT | O_APPEND | O_WRONLY, 0600);
		if (*fd == -1) {
			*fd = STDERR_FILENO;
			str = t_strdup_printf("Can't open log file %s: %m\n",
					      path);
			(void)write_full(STDERR_FILENO, str, strlen(str));
			if (fd == &log_fd)
				failure_exit(FATAL_LOGOPEN);
			else
				i_fatal_status(FATAL_LOGOPEN, "%s", str);
		}
		fd_close_on_exec(*fd, TRUE);
	}
}

void i_set_failure_file(const char *path, const char *prefix)
{
	i_set_failure_prefix("%s", prefix);

	if (log_info_fd != STDERR_FILENO && log_info_fd != log_fd) {
		if (close(log_info_fd) < 0)
			i_error("close(%d) failed: %m", log_info_fd);
	}

	if (log_debug_fd != STDERR_FILENO && log_debug_fd != log_info_fd &&
	    log_debug_fd != log_fd) {
		if (close(log_debug_fd) < 0)
			i_error("close(%d) failed: %m", log_debug_fd);
	}

	open_log_file(&log_fd, path);
	/* if info/debug logs are elsewhere, i_set_info/debug_file()
	   overrides these later. */
	log_info_fd = log_fd;
	log_debug_fd = log_fd;

	i_set_fatal_handler(default_fatal_handler);
	i_set_error_handler(default_error_handler);
	i_set_info_handler(default_error_handler);
	i_set_debug_handler(default_error_handler);
}

static void i_failure_send_option(const char *key, const char *value)
{
	const char *str;

	if (error_handler != i_internal_error_handler)
		return;

	str = t_strdup_printf("\001%c%s %s=%s\n", LOG_TYPE_OPTION+1,
			      my_pid, key, value);
	(void)write_full(STDERR_FILENO, str, strlen(str));
}

void i_set_failure_prefix(const char *prefix_fmt, ...)
{
	va_list args;

	va_start(args, prefix_fmt);
	i_free(log_prefix);
	log_prefix = i_strdup_vprintf(prefix_fmt, args);
	va_end(args);

	log_prefix_sent = FALSE;
}

void i_unset_failure_prefix(void)
{
	i_free(log_prefix);
	log_prefix = i_strdup("");
	log_prefix_sent = FALSE;
}

const char *i_get_failure_prefix(void)
{
	return log_prefix != NULL ? log_prefix : "";
}

static int internal_send_split(string_t *full_str, size_t prefix_len)
{
	string_t *str;
	size_t max_text_len, pos = prefix_len;

	str = t_str_new(PIPE_BUF);
	str_append_data(str, str_data(full_str), prefix_len);
	max_text_len = PIPE_BUF - prefix_len - 1;

	while (pos < str_len(full_str)) {
		str_truncate(str, prefix_len);
		str_append_max(str, str_c(full_str) + pos, max_text_len);
		str_append_c(str, '\n');
		if (log_fd_write(STDERR_FILENO,
				 str_data(str), str_len(str)) < 0)
			return -1;
		pos += max_text_len;
	}
	return 0;
}


static bool line_parse_prefix(const char *line, enum log_type *log_type_r,
			      bool *replace_prefix_r)
{
	if (*line != 1)
		return FALSE;

	unsigned char log_type = (line[1] & 0x7f);
	if (log_type == '\0') {
		i_warning("Broken log line follows (type=NUL)");
		return FALSE;
	}
	log_type--;

	if (log_type > LOG_TYPE_OPTION) {
		i_warning("Broken log line follows (type=%d)", log_type);
		return FALSE;
	}
	*log_type_r = log_type;
	*replace_prefix_r = (line[1] & LOG_TYPE_FLAG_DISABLE_LOG_PREFIX) != 0;
	return TRUE;
}

void i_failure_parse_line(const char *line, struct failure_line *failure)
{

	i_zero(failure);
	if (!line_parse_prefix(line, &failure->log_type,
			       &failure->disable_log_prefix)) {
		failure->log_type = LOG_TYPE_ERROR;
		failure->text = line;
		return;
	}

	line += 2;
	failure->text = line;
	while (*line >= '0' && *line <= '9') {
		failure->pid = failure->pid*10 + (*line - '0');
		line++;
	}
	if (*line != ' ') {
		/* some old protocol? */
		failure->pid = 0;
		return;
	}
	failure->text = line + 1;
}

static void ATTR_NORETURN ATTR_FORMAT(2, 0)
i_internal_fatal_handler(const struct failure_context *ctx,
			 const char *format, va_list args)
{
	failure_handler.v = &internal_handler_vfuncs;
	failure_handler.fatal_err_reset = FATAL_LOGERROR;
	fatal_handler_real(ctx, format, args);


}

static void
i_internal_error_handler(const struct failure_context *ctx,
			 const char *format, va_list args)
{
	failure_handler.v = &internal_handler_vfuncs;
	failure_handler.fatal_err_reset = FATAL_LOGERROR;
	error_handler_real(ctx, format, args);
}

void i_set_failure_internal(void)
{
	fd_set_nonblock(STDERR_FILENO, TRUE);
	i_set_fatal_handler(i_internal_fatal_handler);
	i_set_error_handler(i_internal_error_handler);
	i_set_info_handler(i_internal_error_handler);
	i_set_debug_handler(i_internal_error_handler);
}

bool i_failure_handler_is_internal(failure_callback_t *const callback)
{
	return callback == i_internal_fatal_handler ||
		callback == i_internal_error_handler;
}

void i_set_failure_ignore_errors(bool ignore)
{
	failure_ignore_errors = ignore;
}

void i_set_info_file(const char *path)
{
	if (log_info_fd == log_fd)
		log_info_fd = STDERR_FILENO;

	open_log_file(&log_info_fd, path);
        info_handler = default_error_handler;
	/* write debug-level messages to the info_log_path,
	  until i_set_debug_file() was called */
	log_debug_fd = log_info_fd;
	i_set_debug_handler(default_error_handler);
}

void i_set_debug_file(const char *path)
{
	if (log_debug_fd == log_fd || log_debug_fd == log_info_fd)
		log_debug_fd = STDERR_FILENO;

	open_log_file(&log_debug_fd, path);
	debug_handler = default_error_handler;
}

void i_set_failure_timestamp_format(const char *fmt)
{
	const char *p;

	i_free(log_stamp_format);
	i_free_and_null(log_stamp_format_suffix);

	p = strstr(fmt, "%{usecs}");
	if (p == NULL)
		log_stamp_format = i_strdup(fmt);
	else {
		log_stamp_format = i_strdup_until(fmt, p);
		log_stamp_format_suffix = i_strdup(p + 8);
	}
}

void i_set_failure_send_ip(const struct ip_addr *ip)
{
	i_failure_send_option("ip", net_ip2addr(ip));
}

void i_set_failure_send_prefix(const char *prefix)
{
	i_failure_send_option("prefix", prefix);
}

void i_set_failure_exit_callback(void (*callback)(int *status))
{
	failure_exit_callback = callback;
}

void failures_deinit(void)
{
	if (log_debug_fd == log_info_fd || log_debug_fd == log_fd)
		log_debug_fd = STDERR_FILENO;

	if (log_info_fd == log_fd)
		log_info_fd = STDERR_FILENO;

	if (log_fd != STDERR_FILENO) {
		i_close_fd(&log_fd);
		log_fd = STDERR_FILENO;
	}

	if (log_info_fd != STDERR_FILENO) {
		i_close_fd(&log_info_fd);
		log_info_fd = STDERR_FILENO;
	}

	if (log_debug_fd != STDERR_FILENO) {
		i_close_fd(&log_debug_fd);
		log_debug_fd = STDERR_FILENO;
	}

	i_free_and_null(log_prefix);
	i_free_and_null(log_stamp_format);
	i_free_and_null(log_stamp_format_suffix);
}
