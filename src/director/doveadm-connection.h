#ifndef DOVEADM_CONNECTION_H
#define DOVEADM_CONNECTION_H

struct director;

struct doveadm_connection *
doveadm_connection_init(struct director *dir, int fd);
void doveadm_connections_deinit(void);

void doveadm_connections_kick_callback(struct director *dir);
void doveadm_connections_ring_synced(struct director *dir);

#endif
