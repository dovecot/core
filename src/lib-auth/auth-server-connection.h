#ifndef __AUTH_SERVER_CONNECTION_H
#define __AUTH_SERVER_CONNECTION_H

struct auth_client {
	unsigned int pid;

	struct auth_server_connection *connections;
	struct timeout *to_reconnect;

	unsigned int conn_waiting_handshake_count;

	enum auth_mech available_auth_mechs;
	unsigned int request_id_counter;

	auth_connect_notify_callback_t *connect_notify_callback;
	void *connect_notify_context;
};

struct auth_server_connection {
	struct auth_server_connection *next;

	pool_t pool;
	struct auth_client *client;
	const char *path;
	int fd;

	struct io *io;
	struct istream *input;
	struct ostream *output;

	unsigned int pid;
	enum auth_mech available_auth_mechs;
        struct auth_client_request_reply reply;

        struct hash_table *requests;

	unsigned int handshake_received:1;
	unsigned int reply_received:1;
};

struct auth_server_connection *
auth_server_connection_new(struct auth_client *client, const char *path);
void auth_server_connection_destroy(struct auth_server_connection *conn,
				    int reconnect);

struct auth_server_connection *
auth_server_connection_find_path(struct auth_client *client, const char *path);

struct auth_server_connection *
auth_server_connection_find_mech(struct auth_client *client,
				 enum auth_mech mech, const char **error_r);

#endif
