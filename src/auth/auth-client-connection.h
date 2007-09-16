#ifndef AUTH_CLIENT_CONNECTION_H
#define AUTH_CLIENT_CONNECTION_H

struct auth_client_connection {
	struct auth *auth;
	struct auth_master_listener *listener;
	int refcount;

	int fd;
	struct io *io;
	struct istream *input;
	struct ostream *output;

	unsigned int pid;
	unsigned int connect_uid;
	struct auth_request_handler *request_handler;

	unsigned int version_received:1;
};

struct auth_client_connection *
auth_client_connection_create(struct auth_master_listener *listener, int fd);
void auth_client_connection_destroy(struct auth_client_connection **conn);

struct auth_client_connection *
auth_client_connection_lookup(struct auth_master_listener *listener,
			      unsigned int pid);

void auth_client_connections_init(struct auth_master_listener *listener);
void auth_client_connections_deinit(struct auth_master_listener *listener);

#endif
