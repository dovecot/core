#ifndef AUTH_CLIENT_REQUEST_H
#define AUTH_CLIENT_REQUEST_H

struct auth_server_connection;

bool auth_client_request_is_aborted(struct auth_client_request *request);

void auth_client_request_server_input(struct auth_client_request *request,
				      enum auth_request_status status,
				      const char *const *args);

#endif
