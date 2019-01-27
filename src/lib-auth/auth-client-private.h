#ifndef AUTH_CLIENT_PRIVATE_H
#define AUTH_CLIENT_PRIVATE_H

#include "auth-client.h"

#define AUTH_CONNECT_TIMEOUT_MSECS (30*1000)

struct auth_server_connection {
	pool_t pool;

	struct auth_client *client;
	int fd;
	time_t last_connect;

	struct io *io;
	struct timeout *to;
	struct istream *input;
	struct ostream *output;

	unsigned int server_pid;
	unsigned int connect_uid;
	char *cookie;

	ARRAY(struct auth_mech_desc) available_auth_mechs;

	/* id => request */
	HASH_TABLE(void *, struct auth_client_request *) requests;

	bool version_received:1;
	bool handshake_received:1;
	bool has_plain_mech:1;
	bool connected:1;
};

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
