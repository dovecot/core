#ifndef __AUTH_SERVER_REQUEST_H
#define __AUTH_SERVER_REQUEST_H

int auth_client_input_ok(struct auth_server_connection *conn, const char *args);
int auth_client_input_cont(struct auth_server_connection *conn,
			   const char *args);
int auth_client_input_fail(struct auth_server_connection *conn,
			   const char *args);

void auth_server_requests_remove_all(struct auth_server_connection *conn);

#endif
