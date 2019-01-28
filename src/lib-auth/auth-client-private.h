#ifndef AUTH_CLIENT_PRIVATE_H
#define AUTH_CLIENT_PRIVATE_H

#include "auth-client.h"

#define AUTH_CONNECT_TIMEOUT_MSECS (30*1000)

struct auth_client_request {
	pool_t pool;

	struct auth_server_connection *conn;
	unsigned int id;
	time_t created;

	auth_request_callback_t *callback;
	void *context;
};

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

bool auth_client_request_is_aborted(struct auth_client_request *request);
time_t auth_client_request_get_create_time(struct auth_client_request *request);

void auth_client_request_server_input(struct auth_client_request *request,
				      enum auth_request_status status,
				      const char *const *args);

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
