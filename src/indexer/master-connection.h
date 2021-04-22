#ifndef MASTER_CONNECTION_H
#define MASTER_CONNECTION_H

extern struct master_connection *master_conn;

struct master_connection *
master_connection_create(int fd, struct mail_storage_service_ctx *storage_service);
void master_connection_destroy(void);

#endif
