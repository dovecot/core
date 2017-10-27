#ifndef NOTIFY_CONNECTION_H
#define NOTIFY_CONNECTION_H

struct director;

void notify_connection_init(struct director *dir, int fd);
void notify_connections_deinit(void);

#endif
