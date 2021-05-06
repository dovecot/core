#ifndef MASTER_CONNECTION_H
#define MASTER_CONNECTION_H

bool master_connection_create(struct master_service_connection *conn,
			      struct mail_storage_service_ctx *storage_service);
void master_connections_destroy(void);

#endif
