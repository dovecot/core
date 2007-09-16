#ifndef AUTH_SERVER_REQUEST_H
#define AUTH_SERVER_REQUEST_H

bool auth_client_input_ok(struct auth_server_connection *conn,
			  const char *args);
bool auth_client_input_cont(struct auth_server_connection *conn,
			   const char *args);
bool auth_client_input_fail(struct auth_server_connection *conn,
			    const char *args);

void auth_server_requests_remove_all(struct auth_server_connection *conn);

#endif
