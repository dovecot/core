#ifndef __FAILURES_H
#define __FAILURES_H

#define DEFAULT_FAILURE_STAMP_FORMAT "%b %d %H:%M:%S "

typedef void (*FailureFunc) (const char *, va_list);

void i_panic(const char *format, ...) __attr_format__(1, 2) __attr_noreturn__;
void i_fatal(const char *format, ...) __attr_format__(1, 2) __attr_noreturn__;
void i_error(const char *format, ...) __attr_format__(1, 2);
void i_warning(const char *format, ...) __attr_format__(1, 2);

void i_set_panic_handler(FailureFunc func __attr_noreturn__);
void i_set_fatal_handler(FailureFunc func __attr_noreturn__);
void i_set_error_handler(FailureFunc func);
void i_set_warning_handler(FailureFunc func);

/* send failures to syslog() */
void i_syslog_panic_handler(const char *fmt, va_list args) __attr_noreturn__;
void i_syslog_fatal_handler(const char *fmt, va_list args) __attr_noreturn__;
void i_syslog_error_handler(const char *fmt, va_list args);
void i_syslog_warning_handler(const char *fmt, va_list args);

/* send failures to specified log file instead of stderr. */
void i_set_failure_file(const char *path, const char *prefix);

/* prefix failures with a timestamp. fmt is in strftime() format. */
void i_set_failure_timestamp_format(const char *fmt);

void failures_init(void);
void failures_deinit(void);

#endif
