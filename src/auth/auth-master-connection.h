#ifndef __AUTH_MASTER_CONNECTION_H
#define __AUTH_MASTER_CONNECTION_H

enum listener_type {
	LISTENER_MASTER,
	LISTENER_CLIENT
};

struct auth_master_connection {
	struct auth *auth;

	unsigned int pid;
	int refcount;

	int fd;
	struct istream *input;
	struct ostream *output;
	struct io *io;
	buffer_t *listeners_buf;

	struct auth_client_connection *clients;
	struct timeout *to_clients;

	unsigned int version_received:1;
	unsigned int destroyed:1;
};

#define AUTH_MASTER_IS_DUMMY(master) (master->fd == -1)

struct auth_master_connection *
auth_master_connection_create(struct auth *auth, int fd);
void auth_master_connection_send_handshake(struct auth_master_connection *conn);
void auth_master_connection_destroy(struct auth_master_connection *conn);

void auth_master_request_callback(const char *reply, void *context);

void auth_master_connection_add_listener(struct auth_master_connection *conn,
					 int fd, const char *path,
					 enum listener_type type);

#endif
