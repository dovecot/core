#ifndef __LOGIN_CONNECTION_H
#define __LOGIN_CONNECTION_H

#include "auth-login-interface.h"

struct login_connection {
	struct login_connection *next;

	int fd;
	struct io *io;
	struct istream *input;
	struct ostream *output;

	pool_t pool;
	struct hash_table *auth_requests;

	unsigned int pid;
};

struct login_connection *login_connection_create(int fd);
void login_connection_destroy(struct login_connection *conn);

struct login_connection *login_connection_lookup(unsigned int pid);

void login_connections_init(void);
void login_connections_deinit(void);

#endif
