#ifndef LOG_CONNECTION_H
#define LOG_CONNECTION_H

struct log_connection;

extern bool verbose_proctitle;
extern char *global_log_prefix;

void log_connection_create(struct log_error_buffer *errorbuf,
			   int fd, int listen_fd);

void log_connections_init(void);
void log_connections_deinit(void);

#endif
