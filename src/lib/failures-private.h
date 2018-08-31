#ifndef FAILURES_PRIVATE_H
#define FAILURES_PRIVATE_H

typedef int
failure_write_to_file_t(enum log_type type, string_t *data, size_t prefix_len);
typedef string_t *
failure_format_str_t(const struct failure_context *ctx, size_t *prefix_len_r,
		     const char *format, va_list args);
typedef void failure_on_handler_failure_t(const struct failure_context *ctx);
typedef void failure_post_handler_t(const struct failure_context *ctx);

struct failure_handler_vfuncs {
	failure_write_to_file_t *write;
	failure_format_str_t *format;
	failure_on_handler_failure_t *on_handler_failure;
	failure_post_handler_t *post_handler;
};

struct failure_handler_config {
	int fatal_err_reset;
	struct failure_handler_vfuncs *v;
};

extern struct failure_handler_config failure_handler;

#endif
