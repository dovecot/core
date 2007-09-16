#ifndef FAILURES_H
#define FAILURES_H

/* Default exit status codes that we could use. */
enum fatal_exit_status {
	FATAL_LOGOPEN	= 80, /* Can't open log file */
	FATAL_LOGWRITE  = 81, /* Can't write to log file */
	FATAL_LOGERROR  = 82, /* Internal logging error */
	FATAL_OUTOFMEM	= 83, /* Out of memory */
	FATAL_EXEC	= 84, /* exec() failed */

	FATAL_DEFAULT	= 89
};

#define DEFAULT_FAILURE_STAMP_FORMAT "%b %d %H:%M:%S "

typedef void failure_callback_t(const char *, va_list);
typedef void fatal_failure_callback_t(int status, const char *, va_list);

void i_panic(const char *format, ...) __attr_format__(1, 2) __attr_noreturn__;
void i_fatal(const char *format, ...) __attr_format__(1, 2) __attr_noreturn__;
void i_error(const char *format, ...) __attr_format__(1, 2);
void i_warning(const char *format, ...) __attr_format__(1, 2);
void i_info(const char *format, ...) __attr_format__(1, 2);

void i_fatal_status(int status, const char *format, ...)
	__attr_format__(2, 3) __attr_noreturn__;

/* Change failure handlers. Make sure they don't modify errno. */
void i_set_panic_handler(failure_callback_t *callback __attr_noreturn__);
void i_set_fatal_handler(fatal_failure_callback_t *callback __attr_noreturn__);
void i_set_error_handler(failure_callback_t *callback);
void i_set_warning_handler(failure_callback_t *callback);
void i_set_info_handler(failure_callback_t *callback);

/* Send failures to syslog() */
void i_syslog_panic_handler(const char *fmt, va_list args)
	__attr_noreturn__ __attr_format__(1, 0);
void i_syslog_fatal_handler(int status, const char *fmt, va_list args)
	__attr_noreturn__ __attr_format__(2, 0);
void i_syslog_error_handler(const char *fmt, va_list args)
	__attr_format__(1, 0);
void i_syslog_warning_handler(const char *fmt, va_list args)
	__attr_format__(1, 0);
void i_syslog_info_handler(const char *fmt, va_list args)
	__attr_format__(1, 0);

/* Open syslog and set failure/info handlers to use it. */
void i_set_failure_syslog(const char *ident, int options, int facility);

/* Send failures to specified log file instead of stderr. */
void i_set_failure_file(const char *path, const char *prefix);

/* Send errors to stderr using internal error protocol. */
void i_set_failure_internal(void);

/* Send informational messages to specified log file. i_set_failure_*()
   functions modify the info file too, so call this function after them. */
void i_set_info_file(const char *path);

/* Set the failure prefix. This is used only when logging to a file. */
void i_set_failure_prefix(const char *prefix);

/* Prefix failures with a timestamp. fmt is in strftime() format. */
void i_set_failure_timestamp_format(const char *fmt);

/* Call the callback before exit()ing. The callback may update the status. */
void i_set_failure_exit_callback(void (*callback)(int *status));

void failures_deinit(void);

#endif
