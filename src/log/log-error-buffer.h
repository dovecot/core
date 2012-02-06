#ifndef LOG_ERROR_BUFFER_H
#define LOG_ERROR_BUFFER_H

struct log_error_buffer;

struct log_error {
	enum log_type type;
	time_t timestamp;
	const char *prefix;
	const char *text;
};

struct log_error_buffer *log_error_buffer_init(void);
void log_error_buffer_add(struct log_error_buffer *buf,
			  const struct log_error *error);
void log_error_buffer_deinit(struct log_error_buffer **buf);

struct log_error_buffer_iter *
log_error_buffer_iter_init(struct log_error_buffer *buf);
struct log_error *
log_error_buffer_iter_next(struct log_error_buffer_iter *iter);
void log_error_buffer_iter_deinit(struct log_error_buffer_iter **iter);

#endif
