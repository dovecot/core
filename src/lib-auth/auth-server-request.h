#ifndef __AUTH_SERVER_REQUEST_H
#define __AUTH_SERVER_REQUEST_H

void auth_server_request_handle_reply(struct auth_server_connection *conn,
				      struct auth_client_request_reply *reply,
				      const unsigned char *data);

void auth_server_requests_remove_all(struct auth_server_connection *conn);

#endif
