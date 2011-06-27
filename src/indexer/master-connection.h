#ifndef MASTER_CONNECTION_H
#define MASTER_CONNECTION_H

struct master_connection *
master_connection_create(int fd, struct mail_storage_service_ctx *storage_service);
void master_connection_destroy(struct master_connection **conn);

#endif
