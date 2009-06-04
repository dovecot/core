#ifndef LOG_CONNECTION_H
#define LOG_CONNECTION_H

struct log_connection *log_connection_create(int fd, int listen_fd);
void log_connection_destroy(struct log_connection *log);

void log_connections_init(void);
void log_connections_deinit(void);

#endif
