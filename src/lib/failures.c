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

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <time.h>

static void default_panic_handler(const char *format, va_list args)
	__attr_noreturn__;
static void default_fatal_handler(const char *format, va_list args)
	__attr_noreturn__;

static void default_error_handler(const char *format, va_list args);
static void default_warning_handler(const char *format, va_list args);

/* Initialize working defaults */
static FailureFunc panic_handler __attr_noreturn__ = default_panic_handler;
static FailureFunc fatal_handler __attr_noreturn__ = default_fatal_handler;
static FailureFunc error_handler = default_error_handler;
static FailureFunc warning_handler = default_warning_handler;

static FILE *log_fd = NULL;
static char *log_prefix = NULL, *log_stamp_format = NULL;

static void write_prefix(void)
{
	struct tm *tm;
	char str[256];

	if (log_fd == NULL)
		log_fd = stderr;

	if (log_prefix != NULL)
		fputs(log_prefix, log_fd);

	if (log_stamp_format != NULL) {
		tm = localtime(&ioloop_time);

		if (strftime(str, sizeof(str), log_stamp_format, tm) > 0)
			fputs(str, log_fd);
	}
}

static void default_panic_handler(const char *format, va_list args)
{
	write_prefix();

	fputs("Panic: ", log_fd);
	vfprintf(log_fd, printf_string_fix_format(format), args);
	fputc('\n', log_fd);

	abort();
}

static void default_fatal_handler(const char *format, va_list args)
{
	write_prefix();

	fputs("Fatal: ", log_fd);
	vfprintf(log_fd, printf_string_fix_format(format), args);
	fputc('\n', log_fd);

	exit(98);
}

static void default_error_handler(const char *format, va_list args)
{
	int old_errno = errno;

	write_prefix();

	t_push();
	fputs("Error: ", log_fd);
	vfprintf(log_fd, printf_string_fix_format(format), args);
        fputc('\n', log_fd);
	t_pop();

	fflush(log_fd);

	errno = old_errno;
}

static void default_warning_handler(const char *format, va_list args)
{
	int old_errno = errno;

	write_prefix();

	t_push();
	fputs("Warning: ", log_fd);
	vfprintf(log_fd, printf_string_fix_format(format), args);
	fputc('\n', log_fd);
	t_pop();

	fflush(log_fd);

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
	fatal_handler(format, args);
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

void i_set_panic_handler(FailureFunc func __attr_noreturn__)
{
	if (func == NULL)
		func = default_panic_handler;
        panic_handler = func;
}

void i_set_fatal_handler(FailureFunc func __attr_noreturn__)
{
	if (func == NULL)
		func = default_fatal_handler;
        fatal_handler = func;
}

void i_set_error_handler(FailureFunc func)
{
	if (func == NULL)
		func = default_error_handler;
        error_handler = func;
}

void i_set_warning_handler(FailureFunc func)
{
	if (func == NULL)
		func = default_warning_handler;
        warning_handler = func;
}

void i_syslog_panic_handler(const char *fmt, va_list args)
{
	vsyslog(LOG_CRIT, fmt, args);
        abort();
}

void i_syslog_fatal_handler(const char *fmt, va_list args)
{
	vsyslog(LOG_CRIT, fmt, args);
	exit(98);
}

void i_syslog_error_handler(const char *fmt, va_list args)
{
	vsyslog(LOG_ERR, fmt, args);
}

void i_syslog_warning_handler(const char *fmt, va_list args)
{
	vsyslog(LOG_WARNING, fmt, args);
}

void i_set_failure_file(const char *path, const char *prefix)
{
	if (log_fd != NULL && log_fd != stderr)
		(void)fclose(log_fd);

	log_fd = fopen(path, "a");
	if (log_fd == NULL)
		i_fatal("Can't open log file %s: %m", path);
	fd_close_on_exec(fileno(log_fd), TRUE);

	i_free(log_prefix);
	log_prefix = i_strconcat(prefix, ": ", NULL);
}

void i_set_failure_timestamp_format(const char *fmt)
{
	i_free(log_stamp_format);
        log_stamp_format = i_strdup(fmt);
}

void failures_init(void)
{
}

void failures_deinit(void)
{
	if (log_fd != NULL && log_fd != stderr) {
		(void)fclose(log_fd);
		log_fd = stderr;
	}
}
