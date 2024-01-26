#ifndef AUTH_CLIENT_CONNECTION_H
#define AUTH_CLIENT_CONNECTION_H

#include "login-interface.h"

struct auth_client_connection {
	struct connection conn;
	struct auth *auth;
	struct event *event;
	int refcount;

	unsigned int pid;
	unsigned int connect_uid;
	uint8_t cookie[LOGIN_REQUEST_COOKIE_SIZE];
	struct auth_request_handler *request_handler;

	bool login_requests:1;
	bool version_received:1;
	bool token_auth:1;
};

void auth_client_connection_create(struct auth *auth, int fd, const char *name,
				   bool login_requests, bool token_auth);

struct auth_client_connection *
auth_client_connection_lookup(unsigned int pid);

void auth_client_connections_destroy_all(void);

#endif
