#ifndef AUTH_CLIENT_PRIVATE_H
#define AUTH_CLIENT_PRIVATE_H

#include "connection.h"

#include "auth-client.h"

#define AUTH_CONNECT_TIMEOUT_MSECS (30*1000)

struct auth_client_request {
	pool_t pool;
	enum auth_request_flags flags;
	struct event *event;

	struct auth_client_connection *conn;
	struct timeout *to_fail, *to_final;
	unsigned int id;
	time_t created;

	enum auth_request_status final_status;
	const char *const *final_args;

	buffer_t *cbinding_data;
	auth_channel_binding_callback_t *cbinding_callback;
	void *cbinding_context;

	auth_request_callback_t *callback;
	void *context;

	bool server_finished:1;
	bool removed:1;
};

struct auth_client_connection {
	struct connection conn;
	pool_t pool;

	struct auth_client *client;
	time_t last_connect;

	struct timeout *to;

	unsigned int server_pid;
	unsigned int connect_uid;
	char *cookie;

	ARRAY(struct auth_mech_desc) available_auth_mechs;

	/* id => request */
	HASH_TABLE(void *, struct auth_client_request *) requests;

	bool has_plain_mech:1;
	bool connected:1;
};

struct auth_client {
	char *auth_socket_path;
	unsigned int client_pid;
	struct event *event;

	struct connection_list *clist;
	struct auth_client_connection *conn;
	ARRAY(struct auth_mech_desc) available_auth_mechs;

	auth_connect_notify_callback_t *connect_notify_callback;
	void *connect_notify_context;

	unsigned int request_id_counter;

	unsigned int connect_timeout_msecs;

	bool debug:1;
};

extern struct event_category event_category_auth_client;

bool auth_client_request_is_aborted(struct auth_client_request *request);
time_t auth_client_request_get_create_time(struct auth_client_request *request);

void auth_client_request_server_input(struct auth_client_request **_request,
				      enum auth_request_status status,
				      const char *const *args);

struct connection_list *auth_client_connection_list_init(void);

struct auth_client_connection *
auth_client_connection_init(struct auth_client *client);
void auth_client_connection_deinit(struct auth_client_connection **conn);

int auth_client_connection_connect(struct auth_client_connection *conn);
void auth_client_connection_disconnect(struct auth_client_connection *conn,
				       const char *reason);
void auth_server_reconnect_timeout(struct auth_client_connection *conn);

/* Queues a new request. Must not be called if connection is not connected. */
unsigned int
auth_client_connection_add_request(struct auth_client_connection *conn,
				   struct auth_client_request *request);
void auth_client_connection_remove_request(struct auth_client_connection *conn,
					   struct auth_client_request *request);

#endif
