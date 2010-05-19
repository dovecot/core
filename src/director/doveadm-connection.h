#ifndef DOVEADM_CONNECTION_H
#define DOVEADM_CONNECTION_H

struct director;

struct doveadm_connection *
doveadm_connection_init(struct director *dir, int fd);
void doveadm_connections_deinit(void);

#endif
