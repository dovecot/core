#ifndef __AUTH_MASTER_CONNECTION_H
#define __AUTH_MASTER_CONNECTION_H

#include "auth-master-interface.h"

struct auth_master_connection {
	unsigned int pid;
	int refcount;

	int fd;
	struct ostream *output;
	struct io *io;

	unsigned int request_pos;
	unsigned char request_buf[sizeof(struct auth_master_request)];

	struct auth_client_handshake_reply handshake_reply;
	struct auth_client_connection *clients;
	struct timeout *to_clients;
};

struct auth_master_connection *
auth_master_connection_new(int fd, unsigned int pid);
void auth_master_connection_free(struct auth_master_connection *conn);

#endif
