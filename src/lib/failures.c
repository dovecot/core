/*
 failures.c : Failure manager

    Copyright (c) 2001-2002 Timo Sirainen

    Permission is hereby granted, free of charge, to any person obtaining
    a copy of this software and associated documentation files (the
    "Software"), to deal in the Software without restriction, including
    without limitation the rights to use, copy, modify, merge, publish,
    distribute, sublicense, and/or sell copies of the Software, and to
    permit persons to whom the Software is furnished to do so, subject to
    the following conditions:

    The above copyright notice and this permission notice shall be
    included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
    OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
    MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
    IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
    CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
    TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
    SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/


#include "lib.h"
#include "ioloop.h"
#include "fd-close-on-exec.h"
#include "printf-upper-bound.h"

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <time.h>

static void default_panic_handler(const char *format, va_list args)
	__attr_noreturn__;
static void default_fatal_handler(int status, const char *format, va_list args)
	__attr_noreturn__;

static void default_error_handler(const char *format, va_list args);
static void default_warning_handler(const char *format, va_list args);
static void default_info_handler(const char *format, va_list args);

/* Initialize working defaults */
static failure_callback_t panic_handler __attr_noreturn__ =
	default_panic_handler;
static fatal_failure_callback_t fatal_handler __attr_noreturn__ =
	default_fatal_handler;
static failure_callback_t error_handler = default_error_handler;
static failure_callback_t warning_handler = default_warning_handler;
static failure_callback_t info_handler = default_info_handler;

static FILE *log_fd = NULL, *log_info_fd = NULL;
static char *log_prefix = NULL, *log_stamp_format = NULL;

/* kludgy .. we want to trust log_stamp_format with -Wformat-nonliteral */
static const char *get_log_stamp_format(const char *unused)
	__attr_format_arg__(1);

static const char *get_log_stamp_format(const char *unused __attr_unused__)
{
	return log_stamp_format;
}

static void write_prefix(FILE *f)
{
	struct tm *tm;
	char str[256];

	if (log_prefix != NULL)
		fputs(log_prefix, f);

	if (log_stamp_format != NULL) {
		tm = localtime(&ioloop_time);

		if (strftime(str, sizeof(str),
			     get_log_stamp_format("unused"), tm) > 0)
			fputs(str, f);
	}
}

static int default_handler(const char *prefix, FILE *f,
			   const char *format, va_list args)
{
	static int recursed = 0;
	va_list args2;
	int old_errno = errno;

	if (recursed == 2) {
		/* we're being called from some signal handler, or
		   printf_string_upper_bound() killed us again */
		return -1;
	}

	recursed++;

	if (f == NULL) {
		f = stderr;

		if (log_fd == NULL)
			log_fd = stderr;
	}

	VA_COPY(args2, args);

	t_push();
	if (recursed == 2) {
		/* write without fixing format, that probably killed us
		   last time. */

		/* make sure there's no %n in there */
                (void)printf_string_upper_bound(format, args);
		vfprintf(f, format, args2);
		fputs(" - recursed!", f);
	} else {
		write_prefix(f);

		fputs(prefix, f);
		format = printf_string_fix_format(format);
		/* make sure there's no %n in there */
                (void)printf_string_upper_bound(format, args);
		vfprintf(f, format, args2);
	}

	fputc('\n', f);

	t_pop();

	errno = old_errno;
	recursed--;

	return 0;
}

static void default_panic_handler(const char *format, va_list args)
{
	(void)default_handler("Panic: ", log_fd, format, args);
	abort();
}

static void default_fatal_handler(int status, const char *format, va_list args)
{
	if (default_handler("Fatal: ", log_fd, format, args) < 0 &&
	    status == FATAL_DEFAULT)
		status = FATAL_LOGERROR;

	if (fflush(log_fd) < 0 && status == FATAL_DEFAULT)
		status = FATAL_LOGWRITE;

	exit(status);
}

static void default_error_handler(const char *format, va_list args)
{
	int old_errno = errno;

	if (default_handler("Error: ", log_fd, format, args) < 0)
		exit(FATAL_LOGERROR);

	if (fflush(log_fd) < 0)
		exit(FATAL_LOGWRITE);

	errno = old_errno;
}

static void default_warning_handler(const char *format, va_list args)
{
	int old_errno = errno;

	(void)default_handler("Warning: ", log_fd, format, args);

	if (fflush(log_fd) < 0)
		exit(FATAL_LOGWRITE);

	errno = old_errno;
}

static void default_info_handler(const char *format, va_list args)
{
	int old_errno = errno;

	(void)default_handler("Info: ", log_info_fd, format, args);

	if (fflush(log_info_fd) < 0)
		exit(FATAL_LOGWRITE);

	errno = old_errno;
}

void i_panic(const char *format, ...)
{
	va_list args;

	va_start(args, format);
	panic_handler(format, args);
	va_end(args);
}

void i_fatal(const char *format, ...)
{
	va_list args;

	va_start(args, format);
	fatal_handler(FATAL_DEFAULT, format, args);
	va_end(args);
}

void i_fatal_status(int status, const char *format, ...)
{
	va_list args;

	va_start(args, format);
	fatal_handler(status, format, args);
	va_end(args);
}

void i_error(const char *format, ...)
{
	va_list args;

	va_start(args, format);
	error_handler(format, args);
	va_end(args);
}

void i_warning(const char *format, ...)
{
	va_list args;

	va_start(args, format);
	warning_handler(format, args);
	va_end(args);
}

void i_info(const char *format, ...)
{
	va_list args;

	va_start(args, format);
	info_handler(format, args);
	va_end(args);
}

void i_set_panic_handler(failure_callback_t callback __attr_noreturn__)
{
	if (callback == NULL)
		callback = default_panic_handler;
        panic_handler = callback;
}

void i_set_fatal_handler(fatal_failure_callback_t callback __attr_noreturn__)
{
	if (callback == NULL)
		callback = default_fatal_handler;
        fatal_handler = callback;
}

void i_set_error_handler(failure_callback_t callback)
{
	if (callback == NULL)
		callback = default_error_handler;
        error_handler = callback;
}

void i_set_warning_handler(failure_callback_t callback)
{
	if (callback == NULL)
		callback = default_warning_handler;
        warning_handler = callback;
}

void i_set_info_handler(failure_callback_t callback)
{
	if (callback == NULL)
		callback = default_info_handler;
        info_handler = callback;
}

static int syslog_handler(int level, const char *format, va_list args)
{
	va_list args2;

	static int recursed = 0;

	if (recursed != 0)
		return -1;

	recursed++;

	/* make sure there's no %n in there */
	VA_COPY(args2, args);
	(void)printf_string_upper_bound(format, args);

	vsyslog(level, format, args2);
	recursed--;

	return 0;
}

void i_syslog_panic_handler(const char *fmt, va_list args)
{
	(void)syslog_handler(LOG_CRIT, fmt, args);
        abort();
}

void i_syslog_fatal_handler(int status, const char *fmt, va_list args)
{
	if (syslog_handler(LOG_CRIT, fmt, args) < 0 && status == FATAL_DEFAULT)
		status = FATAL_LOGERROR;
	exit(status);
}

void i_syslog_error_handler(const char *fmt, va_list args)
{
	if (syslog_handler(LOG_ERR, fmt, args) < 0)
		exit(FATAL_LOGERROR);
}

void i_syslog_warning_handler(const char *fmt, va_list args)
{
	(void)syslog_handler(LOG_WARNING, fmt, args);
}

void i_syslog_info_handler(const char *fmt, va_list args)
{
	(void)syslog_handler(LOG_INFO, fmt, args);
}

void i_set_failure_syslog(const char *ident, int options, int facility)
{
	openlog(ident, options, facility);

	i_set_panic_handler(i_syslog_panic_handler);
	i_set_fatal_handler(i_syslog_fatal_handler);
	i_set_error_handler(i_syslog_error_handler);
	i_set_warning_handler(i_syslog_warning_handler);
	i_set_info_handler(i_syslog_info_handler);
}

static void open_log_file(FILE **file, const char *path)
{
	if (*file != NULL && *file != stderr)
		(void)fclose(*file);

	if (path == NULL)
		*file = stderr;
	else {
		*file = fopen(path, "a");
		if (*file == NULL) {
			i_fatal_status(FATAL_LOGOPEN,
				       "Can't open log file %s: %m", path);
		}
		fd_close_on_exec(fileno(*file), TRUE);
	}
}

void i_set_failure_file(const char *path, const char *prefix)
{
	i_free(log_prefix);
	log_prefix = i_strconcat(prefix, ": ", NULL);

	open_log_file(&log_fd, path);

	if (log_info_fd != NULL && log_info_fd != stderr)
		(void)fclose(log_info_fd);
	log_info_fd = log_fd;
}

void i_set_info_file(const char *path)
{
	if (log_info_fd == log_fd)
		log_info_fd = NULL;

	open_log_file(&log_info_fd, path);
        info_handler = default_info_handler;
}

void i_set_failure_timestamp_format(const char *fmt)
{
	i_free(log_stamp_format);
        log_stamp_format = i_strdup(fmt);
}

void failures_deinit(void)
{
	if (log_info_fd == log_fd)
		log_info_fd = NULL;

	if (log_fd != NULL && log_fd != stderr) {
		(void)fclose(log_fd);
		log_fd = stderr;
	}

	if (log_info_fd != NULL && log_info_fd != stderr) {
		(void)fclose(log_info_fd);
		log_info_fd = stderr;
	}
}
