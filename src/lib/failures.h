#ifndef FAILURES_H
#define FAILURES_H

struct ip_addr;

/* Default exit status codes that we could use. */
enum fatal_exit_status {
	FATAL_LOGOPEN	= 80, /* Can't open log file */
	FATAL_LOGWRITE  = 81, /* Can't write to log file */
	FATAL_LOGERROR  = 82, /* Internal logging error */
	FATAL_OUTOFMEM	= 83, /* Out of memory */
	FATAL_EXEC	= 84, /* exec() failed */

	FATAL_DEFAULT	= 89
};

enum log_type {
	LOG_TYPE_DEBUG,
	LOG_TYPE_INFO,
	LOG_TYPE_WARNING,
	LOG_TYPE_ERROR,
	LOG_TYPE_FATAL,
	LOG_TYPE_PANIC,

	LOG_TYPE_COUNT,
	/* special case */
	LOG_TYPE_OPTION
};

struct failure_line {
	pid_t pid;
	enum log_type log_type;
	/* If non-zero, the first log_prefix_len bytes in text indicate
	   the log prefix. This implies disable_log_prefix=TRUE. */
	unsigned int log_prefix_len;
	/* Disable the global log prefix. */
	bool disable_log_prefix;
	const char *text;
};

struct failure_context {
	enum log_type type;
	int exit_status; /* for LOG_TYPE_FATAL */
	const struct tm *timestamp; /* NULL = use time() + localtime() */
	unsigned int timestamp_usecs;
	const char *log_prefix; /* override the default log prefix */
	/* If non-0, insert the log type text (e.g. "Info: ") at this position
	   in the log_prefix instead of appending it. */
	unsigned int log_prefix_type_pos;
};

#define DEFAULT_FAILURE_STAMP_FORMAT "%b %d %H:%M:%S "

typedef void failure_callback_t(const struct failure_context *ctx,
				const char *format, va_list args);

extern const char *failure_log_type_prefixes[];
extern const char *failure_log_type_names[];

void i_log_type(const struct failure_context *ctx, const char *format, ...)
	ATTR_FORMAT(2, 3);
void i_log_typev(const struct failure_context *ctx, const char *format,
		 va_list args) ATTR_FORMAT(2, 0);

void i_panic(const char *format, ...) ATTR_FORMAT(1, 2) ATTR_NORETURN ATTR_COLD;
void i_fatal(const char *format, ...) ATTR_FORMAT(1, 2) ATTR_NORETURN ATTR_COLD;
void i_error(const char *format, ...) ATTR_FORMAT(1, 2) ATTR_COLD;
void i_warning(const char *format, ...) ATTR_FORMAT(1, 2);
void i_info(const char *format, ...) ATTR_FORMAT(1, 2);
void i_debug(const char *format, ...) ATTR_FORMAT(1, 2);

void i_fatal_status(int status, const char *format, ...)
	ATTR_FORMAT(2, 3) ATTR_NORETURN ATTR_COLD;

/* Change failure handlers. */
#ifndef __cplusplus
void i_set_fatal_handler(failure_callback_t *callback ATTR_NORETURN);
#else
/* Older g++ doesn't like attributes in parameters */
void i_set_fatal_handler(failure_callback_t *callback);
#endif
void i_set_error_handler(failure_callback_t *callback);
void i_set_info_handler(failure_callback_t *callback);
void i_set_debug_handler(failure_callback_t *callback);
void i_get_failure_handlers(failure_callback_t **fatal_callback_r,
			    failure_callback_t **error_callback_r,
			    failure_callback_t **info_callback_r,
			    failure_callback_t **debug_callback_r);

/* Send failures to file. */
void default_fatal_handler(const struct failure_context *ctx,
			   const char *format, va_list args)
	ATTR_NORETURN ATTR_FORMAT(2, 0);
void default_error_handler(const struct failure_context *ctx,
			   const char *format, va_list args)
	ATTR_FORMAT(2, 0);

/* Send failures to syslog() */
void i_syslog_fatal_handler(const struct failure_context *ctx,
			    const char *format, va_list args)
	ATTR_NORETURN ATTR_FORMAT(2, 0);
void i_syslog_error_handler(const struct failure_context *ctx,
			    const char *format, va_list args)
	ATTR_FORMAT(2, 0);

/* Open syslog and set failure/info/debug handlers to use it. */
void i_set_failure_syslog(const char *ident, int options, int facility);

/* Send failures to specified log file instead of stderr. */
void i_set_failure_file(const char *path, const char *prefix);

/* Send errors to stderr using internal error protocol. */
void i_set_failure_internal(void);
/* Returns TRUE if the given callback handler was set via
   i_set_failure_internal(). */
bool i_failure_handler_is_internal(failure_callback_t *const callback);
/* If writing to log fails, ignore it instead of existing with
   FATAL_LOGWRITE or FATAL_LOGERROR. */
void i_set_failure_ignore_errors(bool ignore);

/* Send informational messages to specified log file. i_set_failure_*()
   functions modify the info file too, so call this function after them. */
void i_set_info_file(const char *path);

/* Send debug-level message to the given log file. The i_set_info_file() 
   function modifies also the debug log file, so call this function after it. */
void i_set_debug_file(const char *path);

/* Set the failure prefix. */
void i_set_failure_prefix(const char *prefix_fmt, ...) ATTR_FORMAT(1, 2);
/* Set prefix to "". */
void i_unset_failure_prefix(void);
/* Returns the current failure prefix (never NULL). */
const char *i_get_failure_prefix(void);
/* Prefix failures with a timestamp. fmt is in strftime() format. */
void i_set_failure_timestamp_format(const char *fmt);
/* When logging with internal error protocol, update the process's current
   IP address / log prefix by sending it to log process. This is mainly used to
   improve the error message if the process crashes. */
void i_set_failure_send_ip(const struct ip_addr *ip);
void i_set_failure_send_prefix(const char *prefix);

/* Call the callback before exit()ing. The callback may update the status. */
void i_set_failure_exit_callback(void (*callback)(int *status));
/* Call the exit callback and exit() */
void failure_exit(int status) ATTR_NORETURN ATTR_COLD;

/* Parse a line logged using internal failure handler */
void i_failure_parse_line(const char *line, struct failure_line *failure);

void failures_deinit(void);

#endif
