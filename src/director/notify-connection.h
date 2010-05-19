#ifndef NOTIFY_CONNECTION_H
#define NOTIFY_CONNECTION_H

struct director;

struct notify_connection *notify_connection_init(struct director *dir, int fd);
void notify_connection_deinit(struct notify_connection **conn);

#endif
