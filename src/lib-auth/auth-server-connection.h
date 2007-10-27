#ifndef AUTH_SERVER_CONNECTION_H
#define AUTH_SERVER_CONNECTION_H

struct auth_client {
	unsigned int pid;

	struct auth_server_connection *connections;
	struct timeout *to_reconnect;

	time_t missing_sockets_start_time;
	unsigned int conn_waiting_handshake_count;

	buffer_t *available_auth_mechs;
	unsigned int request_id_counter;
	unsigned int last_used_auth_process;

	auth_connect_notify_callback_t *connect_notify_callback;
	void *connect_notify_context;

	unsigned int reconnect:1;
};

struct auth_server_connection {
	struct auth_server_connection *next;

	pool_t pool;
	int refcount;

	struct auth_client *client;
	const char *path;
	int fd;

	struct io *io;
	struct timeout *to;
	struct istream *input;
	struct ostream *output;

	unsigned int server_pid;
	unsigned int connect_uid;

	buffer_t *auth_mechs_buf;
	const struct auth_mech_desc *available_auth_mechs;
	unsigned int available_auth_mechs_count;

        struct hash_table *requests;

	unsigned int version_received:1;
	unsigned int handshake_received:1;
	unsigned int has_plain_mech:1;
};

struct auth_server_connection *
auth_server_connection_new(struct auth_client *client, const char *path);
void auth_server_connection_destroy(struct auth_server_connection **conn,
				    bool reconnect);

struct auth_server_connection *
auth_server_connection_find_path(struct auth_client *client, const char *path);

struct auth_server_connection *
auth_server_connection_find_mech(struct auth_client *client,
				 const char *name, const char **error_r);

#endif
