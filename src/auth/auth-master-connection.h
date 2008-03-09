#ifndef AUTH_MASTER_CONNECTION_H
#define AUTH_MASTER_CONNECTION_H

struct auth_stream_reply;

struct auth_master_connection {
	struct auth_master_listener *listener;
	int refcount;

	int fd;
	struct istream *input;
	struct ostream *output;
	struct io *io;

	unsigned int version_received:1;
	unsigned int destroyed:1;
};

struct auth_master_connection *
auth_master_connection_create(struct auth_master_listener *listener, int fd);
void auth_master_connection_destroy(struct auth_master_connection **conn);

void auth_master_connection_ref(struct auth_master_connection *conn);
void auth_master_connection_unref(struct auth_master_connection **conn);

void auth_master_connection_send_handshake(struct auth_master_connection *conn);
void auth_master_connections_send_handshake(void);

void auth_master_request_callback(struct auth_stream_reply *reply,
				  void *context);

#endif
