#ifndef AUTH_CLIENT_CONNECTION_H
#define AUTH_CLIENT_CONNECTION_H

#include "master-auth.h"

struct auth_client_connection {
	struct auth *auth;
	int refcount;

	int fd;
	struct io *io;
	struct istream *input;
	struct ostream *output;

	unsigned int pid;
	unsigned int connect_uid;
	uint8_t cookie[MASTER_AUTH_COOKIE_SIZE];
	struct auth_request_handler *request_handler;

	unsigned int login_requests:1;
	unsigned int version_received:1;
};

struct auth_client_connection *
auth_client_connection_create(struct auth *auth, int fd, bool login_requests);
void auth_client_connection_destroy(struct auth_client_connection **conn);

struct auth_client_connection *
auth_client_connection_lookup(unsigned int pid);

void auth_client_connections_init(void);
void auth_client_connections_deinit(void);

#endif
