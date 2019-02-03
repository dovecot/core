#ifndef AUTH_CLIENT_PRIVATE_H
#define AUTH_CLIENT_PRIVATE_H

#include "auth-client.h"

#define AUTH_CONNECT_TIMEOUT_MSECS (30*1000)

struct auth_client {
	char *auth_socket_path;
	unsigned int client_pid;

	struct auth_server_connection *conn;

	auth_connect_notify_callback_t *connect_notify_callback;
	void *connect_notify_context;

	unsigned int request_id_counter;

	unsigned int connect_timeout_msecs;

	bool debug:1;
};

#endif
