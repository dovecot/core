#ifndef NOTIFY_CONNECTION_H
#define NOTIFY_CONNECTION_H

void notify_connection_create(int fd, bool fifo);
void notify_connections_destroy_all(void);

void notify_connection_sync_callback(bool success, void *context);

#endif
