#ifndef AUTH_MASTER_CONNECTION_H
#define AUTH_MASTER_CONNECTION_H

struct auth_stream_reply;

struct auth_master_connection {
	struct auth *auth;
	int refcount;

	int fd;
	struct istream *input;
	struct ostream *output;
	struct io *io;

	struct auth_request_list *requests;

	unsigned int version_received:1;
	unsigned int destroyed:1;
	unsigned int userdb_only:1;
};
ARRAY_DEFINE_TYPE(auth_master_connections, struct auth_master_connection *);

extern ARRAY_TYPE(auth_master_connections) auth_master_connections;

struct auth_master_connection *
auth_master_connection_create(struct auth *auth, int fd, bool userdb_only);
void auth_master_connection_destroy(struct auth_master_connection **conn);

void auth_master_connection_ref(struct auth_master_connection *conn);
void auth_master_connection_unref(struct auth_master_connection **conn);

void auth_master_request_callback(struct auth_stream_reply *reply,
				  void *context);

void auth_master_connections_init(void);
void auth_master_connections_deinit(void);

#endif
