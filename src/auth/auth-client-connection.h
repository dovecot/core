#ifndef __AUTH_CLIENT_CONNECTION_H
#define __AUTH_CLIENT_CONNECTION_H

struct auth_client_connection {
	struct auth_client_connection *next;

	struct auth_master_connection *master;
	int refcount;

	int fd;
	struct io *io;
	struct istream *input;
	struct ostream *output;

	pool_t pool;
	struct hash_table *auth_requests;
	char *default_protocol;

	unsigned int pid;
	unsigned int connect_uid;
	unsigned int version_received:1;
};

struct auth_client_connection *
auth_client_connection_create(struct auth_master_connection *master, int fd);
void auth_client_connection_destroy(struct auth_client_connection *conn);

struct auth_client_connection *
auth_client_connection_lookup(struct auth_master_connection *master,
			      unsigned int pid);

void auth_client_connections_init(struct auth_master_connection *master);
void auth_client_connections_deinit(struct auth_master_connection *master);

#endif
