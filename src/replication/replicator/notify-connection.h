#ifndef NOTIFY_CONNECTION_H
#define NOTIFY_CONNECTION_H

struct replicator_queue;

struct notify_connection *
notify_connection_create(int fd, struct replicator_queue *queue);
void notify_connection_ref(struct notify_connection *conn);
void notify_connection_unref(struct notify_connection **conn);

void notify_connections_destroy_all(void);

#endif
