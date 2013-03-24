#ifndef DOVEADM_CONNECTION_H
#define DOVEADM_CONNECTION_H

void doveadm_connection_create(struct replicator_queue *queue, int fd);

void doveadm_connections_init(void);
void doveadm_connections_deinit(void);

#endif
