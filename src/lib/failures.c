/* Copyright (c) 2002-2007 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "str.h"
#include "backtrace-string.h"
#include "printf-format-fix.h"
#include "write-full.h"
#include "fd-close-on-exec.h"

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <syslog.h>
#include <time.h>

const char *failure_log_type_prefixes[] = {
	"Info: ",
	"Warning: ",
	"Error: ",
	"Fatal: ",
	"Panic: "
};
static char log_type_internal_chars[] = {
	'I', 'W', 'E', 'F', 'P'
};

static void default_fatal_handler(enum log_type type, int status,
				  const char *format, va_list args)
	ATTR_NORETURN ATTR_FORMAT(3, 0);
static void default_error_handler(enum log_type type, const char *format,
				  va_list args) ATTR_FORMAT(2, 0);

/* Initialize working defaults */
static fatal_failure_callback_t *fatal_handler ATTR_NORETURN =
	default_fatal_handler;
static failure_callback_t *error_handler = default_error_handler;
static failure_callback_t *info_handler = default_error_handler;
static void (*failure_exit_callback)(int *) = NULL;

static int log_fd = STDERR_FILENO, log_info_fd = STDERR_FILENO;
static char *log_prefix = NULL, *log_stamp_format = NULL;

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

static void log_prefix_add(string_t *str)
{
	struct tm *tm;
	char buf[256];
	time_t now;

	if (log_prefix != NULL)
		str_append(str, log_prefix);

	if (log_stamp_format != NULL) {
		now = time(NULL);
		tm = localtime(&now);

		if (strftime(buf, sizeof(buf),
			     get_log_stamp_format("unused"), tm) > 0)
			str_append(str, buf);
	}
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

	while ((ret = write(fd, data, len)) != (ssize_t)len) {
		if (ret > 0) {
			/* some was written, continue.. */
			data += ret;
			len -= ret;
			continue;
		}
		if (ret == 0) {
			/* out of disk space? */
			return -1;
		}
		if (errno != EAGAIN)
			return -1;

		/* wait until we can write more. this can happen at least
		   when writing to terminal, even if fd is blocking. */
		ioloop = io_loop_create();
		io = io_add(IO_WRITE, fd, log_fd_flush_stop, ioloop);
		io_loop_run(ioloop);
		io_remove(&io);
		io_loop_destroy(&ioloop);
	}
	return 0;
}

static int ATTR_FORMAT(3, 0)
default_handler(const char *prefix, int fd, const char *format, va_list args)
{
	static int recursed = 0;
	int ret, old_errno = errno;

	if (recursed >= 2) {
		/* we're being called from some signal handler or we ran
		   out of memory */
		return 0;
	}

	recursed++;

	T_FRAME(
		string_t *str = t_str_new(256);
		log_prefix_add(str);
		str_append(str, prefix);

		/* make sure there's no %n in there and fix %m */
		str_vprintfa(str, printf_format_fix(format), args);
		str_append_c(str, '\n');

		ret = log_fd_write(fd, str_data(str), str_len(str));
	);

	errno = old_errno;
	recursed--;

	return ret;
}

static void ATTR_FORMAT(3, 0)
default_fatal_handler(enum log_type type, int status,
		      const char *format, va_list args)
{
	const char *backtrace;

	if (default_handler(failure_log_type_prefixes[type], log_fd, format,
			    args) < 0 && status == FATAL_DEFAULT)
		status = FATAL_LOGWRITE;

	if (type == LOG_TYPE_PANIC) {
		if (backtrace_get(&backtrace) == 0)
			i_error("Raw backtrace: %s", backtrace);
	}

	if (type == LOG_TYPE_PANIC)
		abort();
	else
		failure_exit(status);
}

static void ATTR_FORMAT(2, 0)
default_error_handler(enum log_type type, const char *format, va_list args)
{
	int fd = type == LOG_TYPE_INFO ? log_info_fd : log_fd;

	if (default_handler(failure_log_type_prefixes[type],
			    fd, format, args) < 0)
		failure_exit(FATAL_LOGWRITE);
}

void i_log_type(enum log_type type, const char *format, ...)
{
	va_list args;

	va_start(args, format);
	if (type == LOG_TYPE_INFO)
		info_handler(type, format, args);
	else
		error_handler(type, format, args);
	va_end(args);
}

void i_panic(const char *format, ...)
{
	va_list args;

	va_start(args, format);
	fatal_handler(LOG_TYPE_PANIC, 0, format, args);
	va_end(args);
}

void i_fatal(const char *format, ...)
{
	va_list args;

	va_start(args, format);
	fatal_handler(LOG_TYPE_FATAL, FATAL_DEFAULT, format, args);
	va_end(args);
}

void i_fatal_status(int status, const char *format, ...)
{
	va_list args;

	va_start(args, format);
	fatal_handler(LOG_TYPE_FATAL, status, format, args);
	va_end(args);
}

void i_error(const char *format, ...)
{
	int old_errno = errno;
	va_list args;

	va_start(args, format);
	error_handler(LOG_TYPE_ERROR, format, args);
	va_end(args);

	errno = old_errno;
}

void i_warning(const char *format, ...)
{
	int old_errno = errno;
	va_list args;

	va_start(args, format);
	error_handler(LOG_TYPE_WARNING, format, args);
	va_end(args);

	errno = old_errno;
}

void i_info(const char *format, ...)
{
	int old_errno = errno;
	va_list args;

	va_start(args, format);
	info_handler(LOG_TYPE_INFO, format, args);
	va_end(args);

	errno = old_errno;
}

void i_set_fatal_handler(fatal_failure_callback_t *callback ATTR_NORETURN)
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

static int ATTR_FORMAT(2, 0)
syslog_handler(int level, const char *format, va_list args)
{
	static int recursed = 0;

	if (recursed != 0)
		return -1;

	recursed++;

	/* make sure there's no %n in there. vsyslog() supports %m, but since
	   we'll convert it ourself anyway, we might as well it */
	vsyslog(level, printf_format_fix_unsafe(format), args);
	recursed--;

	return 0;
}

void i_syslog_fatal_handler(enum log_type type, int status,
			    const char *fmt, va_list args)
{
	const char *backtrace;
	if (syslog_handler(LOG_CRIT, fmt, args) < 0 && status == FATAL_DEFAULT)
		status = FATAL_LOGERROR;

	if (type == LOG_TYPE_PANIC) {
		if (backtrace_get(&backtrace) == 0)
			i_error("Raw backtrace: %s", backtrace);
		abort();
	} else {
		failure_exit(status);
	}
}

void i_syslog_error_handler(enum log_type type, const char *fmt, va_list args)
{
	int level = LOG_ERR;

	switch (type) {
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
	}

	if (syslog_handler(level, fmt, args) < 0)
		failure_exit(FATAL_LOGERROR);
}

void i_set_failure_syslog(const char *ident, int options, int facility)
{
	openlog(ident, options, facility);

	i_set_fatal_handler(i_syslog_fatal_handler);
	i_set_error_handler(i_syslog_error_handler);
	i_set_info_handler(i_syslog_error_handler);
}

static void open_log_file(int *fd, const char *path)
{
	char buf[PATH_MAX];

	if (*fd != STDERR_FILENO) {
		if (close(*fd) < 0) {
			i_snprintf(buf, sizeof(buf),
				   "close(%d) failed: %m", *fd);
			(void)write_full(STDERR_FILENO, buf, strlen(buf));
		}
	}

	if (path == NULL || strcmp(path, "/dev/stderr") == 0)
		*fd = STDERR_FILENO;
	else {
		*fd = open(path, O_CREAT | O_APPEND | O_WRONLY, 0600);
		if (*fd == -1) {
			*fd = STDERR_FILENO;
			i_snprintf(buf, sizeof(buf),
				   "Can't open log file %s: %m", path);
			(void)write_full(STDERR_FILENO, buf, strlen(buf));
			failure_exit(FATAL_LOGOPEN);
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

	open_log_file(&log_fd, path);
	log_info_fd = log_fd;

	i_set_fatal_handler(NULL);
	i_set_error_handler(NULL);
	i_set_info_handler(NULL);
}

void i_set_failure_prefix(const char *prefix)
{
	i_free(log_prefix);
	log_prefix = i_strdup(prefix);
}

static int ATTR_FORMAT(2, 0)
internal_handler(char log_type, const char *format, va_list args)
{
	int ret;

	T_FRAME(
		string_t *str;

		str = t_str_new(512);
		str_append_c(str, 1);
		str_append_c(str, log_type);
		str_vprintfa(str, format, args);
		str_append_c(str, '\n');
		ret = write_full(2, str_data(str), str_len(str));
	);

	return ret;
}

static void ATTR_NORETURN ATTR_FORMAT(3, 0)
i_internal_fatal_handler(enum log_type type, int status,
			 const char *fmt, va_list args)
{
	const char *backtrace;

	if (internal_handler(log_type_internal_chars[type], fmt, args) < 0 &&
	    status == FATAL_DEFAULT)
		status = FATAL_LOGERROR;

	if (type == LOG_TYPE_PANIC) {
		if (backtrace_get(&backtrace) == 0)
			i_error("Raw backtrace: %s", backtrace);
		abort();
	} else {
		failure_exit(status);
	}
}

static void ATTR_FORMAT(2, 0)
i_internal_error_handler(enum log_type type, const char *fmt, va_list args)
{
	if (internal_handler(log_type_internal_chars[type], fmt, args) < 0)
		failure_exit(FATAL_LOGERROR);
}

void i_set_failure_internal(void)
{
	i_set_fatal_handler(i_internal_fatal_handler);
	i_set_error_handler(i_internal_error_handler);
	i_set_info_handler(i_internal_error_handler);
}

void i_set_info_file(const char *path)
{
	if (log_info_fd == log_fd)
		log_info_fd = STDERR_FILENO;

	open_log_file(&log_info_fd, path);
        info_handler = default_error_handler;
}

void i_set_failure_timestamp_format(const char *fmt)
{
	i_free(log_stamp_format);
        log_stamp_format = i_strdup(fmt);
}

void i_set_failure_exit_callback(void (*callback)(int *status))
{
	failure_exit_callback = callback;
}

void failures_deinit(void)
{
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

	i_free_and_null(log_prefix);
	i_free_and_null(log_stamp_format);
}
