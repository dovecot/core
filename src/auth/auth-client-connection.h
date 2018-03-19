#ifndef AUTH_CLIENT_CONNECTION_H
#define AUTH_CLIENT_CONNECTION_H

#include "master-auth.h"

struct auth_client_connection {
	struct auth_client_connection *prev, *next;
	struct auth *auth;
	struct event *event;
	int refcount;

	int fd;
	struct io *io;
	struct istream *input;
	struct ostream *output;

	unsigned int version_minor;
	unsigned int pid;
	unsigned int connect_uid;
	uint8_t cookie[MASTER_AUTH_COOKIE_SIZE];
	struct auth_request_handler *request_handler;

	bool login_requests:1;
	bool version_received:1;
	bool token_auth:1;
};

void auth_client_connection_create(struct auth *auth, int fd,
				   bool login_requests, bool token_auth);
void auth_client_connection_destroy(struct auth_client_connection **conn);

struct auth_client_connection *
auth_client_connection_lookup(unsigned int pid);

void auth_client_connections_destroy_all(void);

#endif
