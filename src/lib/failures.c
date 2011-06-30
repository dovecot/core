/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "str.h"
#include "hostpid.h"
#include "network.h"
#include "lib-signals.h"
#include "backtrace-string.h"
#include "printf-format-fix.h"
#include "write-full.h"
#include "fd-close-on-exec.h"

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <syslog.h>
#include <time.h>

const char *failure_log_type_prefixes[LOG_TYPE_COUNT] = {
	"Debug: ",
	"Info: ",
	"Warning: ",
	"Error: ",
	"Fatal: ",
	"Panic: "
};

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
static char *log_prefix = NULL, *log_stamp_format = NULL;
static bool failure_ignore_errors = FALSE, log_prefix_sent = FALSE;

static void ATTR_FORMAT(2, 0)
i_internal_error_handler(const struct failure_context *ctx,
			 const char *format, va_list args);

/* kludgy .. we want to trust log_stamp_format with -Wformat-nonliteral */
static const char *get_log_stamp_format(const char *unused)
	ATTR_FORMAT_ARG(1);

static const char *get_log_stamp_format(const char *unused ATTR_UNUSED)
{
	return log_stamp_format;
}

void failure_exit(int status)
{
	if (failure_exit_callback != NULL)
		failure_exit_callback(&status);
	exit(status);
}

static void log_prefix_add(const struct failure_context *ctx, string_t *str)
{
	const struct tm *tm = ctx->timestamp;
	char buf[256];
	time_t now;

	if (log_stamp_format != NULL) {
		if (tm == NULL) {
			now = time(NULL);
			tm = localtime(&now);
		}

		if (strftime(buf, sizeof(buf),
			     get_log_stamp_format("unused"), tm) > 0)
			str_append(str, buf);
	}
	if (log_prefix != NULL)
		str_append(str, log_prefix);
}

static void log_fd_flush_stop(struct ioloop *ioloop)
{
	io_loop_stop(ioloop);
}

static int log_fd_write(int fd, const unsigned char *data, unsigned int len)
{
	struct ioloop *ioloop;
	struct io *io;
	ssize_t ret;
	unsigned int prev_signal_term_counter = signal_term_counter;
	unsigned int terminal_eintr_count = 0;

	while ((ret = write(fd, data, len)) != (ssize_t)len) {
		if (ret > 0) {
			/* some was written, continue.. */
			data += ret;
			len -= ret;
			continue;
		}
		if (ret == 0) {
			/* out of disk space? */
			errno = ENOSPC;
			return -1;
		}
		switch (errno) {
		case EAGAIN:
			/* wait until we can write more. this can happen at
			   least when writing to terminal, even if fd is
			   blocking. */
			ioloop = io_loop_create();
			io = io_add(fd, IO_WRITE, log_fd_flush_stop, ioloop);
			io_loop_run(ioloop);
			io_remove(&io);
			io_loop_destroy(&ioloop);
			break;
		case EINTR:
			if (prev_signal_term_counter == signal_term_counter) {
				/* non-terminal signal. ignore. */
			} else if (terminal_eintr_count++ == 0) {
				/* we'd rather not die in the middle of
				   writing to log. try again once more */
			} else {
				/* received two terminal signals.
				   someone wants us dead. */
				return -1;
			}
			break;
		default:
			return -1;
		}
		prev_signal_term_counter = signal_term_counter;
	}
	return 0;
}

static int ATTR_FORMAT(3, 0)
default_handler(const struct failure_context *ctx, int fd,
		const char *format, va_list args)
{
	static int recursed = 0;
	int ret;

	if (recursed >= 2) {
		/* we're being called from some signal handler or we ran
		   out of memory */
		return -1;
	}

	recursed++;
	T_BEGIN {
		string_t *str = t_str_new(256);
		log_prefix_add(ctx, str);
		str_append(str, failure_log_type_prefixes[ctx->type]);

		/* make sure there's no %n in there and fix %m */
		str_vprintfa(str, printf_format_fix(format), args);
		str_append_c(str, '\n');

		ret = log_fd_write(fd, str_data(str), str_len(str));
	} T_END;

	if (ret < 0 && failure_ignore_errors)
		ret = 0;

	recursed--;
	return ret;
}

static void ATTR_NORETURN
default_fatal_finish(enum log_type type, int status)
{
	const char *backtrace;

	if (type == LOG_TYPE_PANIC || status == FATAL_OUTOFMEM) {
		if (backtrace_get(&backtrace) == 0)
			i_error("Raw backtrace: %s", backtrace);
	}

	if (type == LOG_TYPE_PANIC)
		abort();
	else
		failure_exit(status);
}

void default_fatal_handler(const struct failure_context *ctx,
			   const char *format, va_list args)
{
	int status = ctx->exit_status;

	if (default_handler(ctx, log_fd, format, args) < 0 &&
	    status == FATAL_DEFAULT)
		status = FATAL_LOGWRITE;

	default_fatal_finish(ctx->type, status);
}

void default_error_handler(const struct failure_context *ctx,
			   const char *format, va_list args)
{
	int fd;

	switch (ctx->type) {
	case LOG_TYPE_DEBUG:
		fd = log_debug_fd;
		break;
	case LOG_TYPE_INFO:
		fd = log_info_fd;
		break;
	default:
		fd = log_fd;
	}

	if (default_handler(ctx, fd, format, args) < 0) {
		if (fd == log_fd)
			failure_exit(FATAL_LOGWRITE);
		/* we failed to log to info/debug log, try to log the
		   write error to error log - maybe that'll work. */
		i_fatal_status(FATAL_LOGWRITE, "write() failed to %s log: %m",
			       fd == log_info_fd ? "info" : "debug");
	}
}

void i_log_type(const struct failure_context *ctx, const char *format, ...)
{
	va_list args;

	va_start(args, format);

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

	va_end(args);
}

void i_panic(const char *format, ...)
{
	struct failure_context ctx;
	va_list args;

	memset(&ctx, 0, sizeof(ctx));
	ctx.type = LOG_TYPE_PANIC;

	va_start(args, format);
	fatal_handler(&ctx, format, args);
	va_end(args);
}

void i_fatal(const char *format, ...)
{
	struct failure_context ctx;
	va_list args;

	memset(&ctx, 0, sizeof(ctx));
	ctx.type = LOG_TYPE_FATAL;
	ctx.exit_status = FATAL_DEFAULT;

	va_start(args, format);
	fatal_handler(&ctx, format, args);
	va_end(args);
}

void i_fatal_status(int status, const char *format, ...)
{
	struct failure_context ctx;
	va_list args;

	memset(&ctx, 0, sizeof(ctx));
	ctx.type = LOG_TYPE_FATAL;
	ctx.exit_status = status;

	va_start(args, format);
	fatal_handler(&ctx, format, args);
	va_end(args);
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
	if (callback == NULL)
		callback = default_fatal_handler;
        fatal_handler = callback;
}

void i_set_error_handler(failure_callback_t *callback)
{
	if (callback == NULL)
		callback = default_error_handler;
	error_handler = callback;
}

void i_set_info_handler(failure_callback_t *callback)
{
	if (callback == NULL)
		callback = default_error_handler;
	info_handler = callback;
}

void i_set_debug_handler(failure_callback_t *callback)
{
	if (callback == NULL)
		callback = default_error_handler;
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

static int ATTR_FORMAT(3, 0)
syslog_handler(int level, enum log_type type, const char *format, va_list args)
{
	static int recursed = 0;

	if (recursed >= 2)
		return -1;
	recursed++;

	/* syslogs don't generatelly bother to log the level in any way,
	   so make sure errors are shown clearly */
	T_BEGIN {
		syslog(level, "%s%s%s",
		       log_prefix == NULL ? "" : log_prefix,
		       type != LOG_TYPE_INFO ?
		       failure_log_type_prefixes[type] : "",
		       t_strdup_vprintf(format, args));
	} T_END;
	recursed--;
	return 0;
}

void i_syslog_fatal_handler(const struct failure_context *ctx,
			    const char *format, va_list args)
{
	int status = ctx->exit_status;

	if (syslog_handler(LOG_CRIT, ctx->type, format, args) < 0 &&
	    status == FATAL_DEFAULT)
		status = FATAL_LOGERROR;

	default_fatal_finish(ctx->type, status);
}

void i_syslog_error_handler(const struct failure_context *ctx,
			    const char *format, va_list args)
{
	int level = LOG_ERR;

	switch (ctx->type) {
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

	if (syslog_handler(level, ctx->type, format, args) < 0)
		failure_exit(FATAL_LOGERROR);
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
			str = t_strdup_printf("close(%d) failed: %m", *fd);
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
	i_set_failure_prefix(prefix);

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

	i_set_fatal_handler(NULL);
	i_set_error_handler(NULL);
	i_set_info_handler(NULL);
	i_set_debug_handler(NULL);
}

static void i_failure_send_option(const char *key, const char *value)
{
	const char *str;

	if (error_handler != i_internal_error_handler)
		return;

	str = t_strdup_printf("\001%c%s %s=%s\n", LOG_TYPE_OPTION+1,
			      my_pid, key, value);
	(void)write_full(2, str, strlen(str));
}

void i_set_failure_prefix(const char *prefix)
{
	i_free(log_prefix);
	log_prefix = i_strdup(prefix);

	log_prefix_sent = FALSE;
}

static int internal_send_split(string_t *full_str, unsigned int prefix_len)
{
	string_t *str;
	unsigned int max_text_len, pos = prefix_len;

	str = t_str_new(PIPE_BUF);
	str_append_n(str, str_c(full_str), prefix_len);
	max_text_len = PIPE_BUF - prefix_len - 1;

	while (pos < str_len(full_str)) {
		str_truncate(str, prefix_len);
		str_append_n(str, str_c(full_str) + pos, max_text_len);
		str_append_c(str, '\n');
		if (log_fd_write(STDERR_FILENO,
				 str_data(str), str_len(str)) < 0)
			return -1;
		pos += max_text_len;
	}
	return 0;
}

static int ATTR_FORMAT(2, 0)
internal_handler(const struct failure_context *ctx,
		 const char *format, va_list args)
{
	static int recursed = 0;
	int ret;

	if (recursed >= 2) {
		/* we're being called from some signal handler or we ran
		   out of memory */
		return -1;
	}

	recursed++;
	T_BEGIN {
		string_t *str;
		unsigned int prefix_len;

		if (!log_prefix_sent && log_prefix != NULL) {
			log_prefix_sent = TRUE;
			i_failure_send_option("prefix", log_prefix);
		}

		str = t_str_new(128);
		str_printfa(str, "\001%c%s ", ctx->type + 1, my_pid);
		prefix_len = str_len(str);

		str_vprintfa(str, format, args);
		if (str_len(str)+1 <= PIPE_BUF) {
			str_append_c(str, '\n');
			ret = log_fd_write(STDERR_FILENO,
					   str_data(str), str_len(str));
		} else {
			ret = internal_send_split(str, prefix_len);
		}
	} T_END;

	if (ret < 0 && failure_ignore_errors)
		ret = 0;

	recursed--;
	return ret;
}

static bool line_is_ok(const char *line)
{
	if (*line != 1)
		return FALSE;

	if (line[1] == '\0') {
		i_warning("Broken log line follows (type=NUL)");
		return FALSE;
	}

	if (line[1]-1 > LOG_TYPE_OPTION) {
		i_warning("Broken log line follows (type=%d)", line[1]-1);
		return FALSE;
	}
	return TRUE;
}

void i_failure_parse_line(const char *line, struct failure_line *failure)
{
	memset(failure, 0, sizeof(*failure));
	if (!line_is_ok(line)) {
		failure->log_type = LOG_TYPE_ERROR;
		failure->text = line;
		return;
	}
	failure->log_type = line[1] - 1;

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
	int status = ctx->exit_status;

	if (internal_handler(ctx, format, args) < 0 &&
	    status == FATAL_DEFAULT)
		status = FATAL_LOGERROR;

	default_fatal_finish(ctx->type, status);
}

static void
i_internal_error_handler(const struct failure_context *ctx,
			 const char *format, va_list args)
{
	if (internal_handler(ctx, format, args) < 0)
		failure_exit(FATAL_LOGERROR);
}

void i_set_failure_internal(void)
{
	i_set_fatal_handler(i_internal_fatal_handler);
	i_set_error_handler(i_internal_error_handler);
	i_set_info_handler(i_internal_error_handler);
	i_set_debug_handler(i_internal_error_handler);
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
	i_set_debug_handler(NULL);
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
	i_free(log_stamp_format);
        log_stamp_format = i_strdup(fmt);
}

void i_set_failure_ip(const struct ip_addr *ip)
{
	i_failure_send_option("ip", net_ip2addr(ip));
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
		(void)close(log_fd);
		log_fd = STDERR_FILENO;
	}

	if (log_info_fd != STDERR_FILENO) {
		(void)close(log_info_fd);
		log_info_fd = STDERR_FILENO;
	}

	if (log_debug_fd != STDERR_FILENO) {
		(void)close(log_debug_fd);
		log_debug_fd = STDERR_FILENO;
	}

	i_free_and_null(log_prefix);
	i_free_and_null(log_stamp_format);
}
