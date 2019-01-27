#ifndef AUTH_SERVER_CONNECTION_H
#define AUTH_SERVER_CONNECTION_H

struct auth_server_connection *
auth_server_connection_init(struct auth_client *client);
void auth_server_connection_deinit(struct auth_server_connection **conn);

int auth_server_connection_connect(struct auth_server_connection *conn);
void auth_server_connection_disconnect(struct auth_server_connection *conn,
				       const char *reason);

/* Queues a new request. Must not be called if connection is not connected. */
unsigned int
auth_server_connection_add_request(struct auth_server_connection *conn,
				   struct auth_client_request *request);
void auth_server_connection_remove_request(struct auth_server_connection *conn,
					   unsigned int id);
#endif
