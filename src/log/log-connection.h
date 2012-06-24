#ifndef LOG_CONNECTION_H
#define LOG_CONNECTION_H

struct log_connection;

void log_connection_create(struct log_error_buffer *errorbuf,
			   int fd, int listen_fd);

void log_connections_init(void);
void log_connections_deinit(void);

#endif
