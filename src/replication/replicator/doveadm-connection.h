#ifndef DOVEADM_CONNECTION_H
#define DOVEADM_CONNECTION_H

struct replicator_brain;

void doveadm_connection_create(struct replicator_brain *brain, int fd);

void doveadm_connections_init(void);
void doveadm_connections_deinit(void);

#endif
