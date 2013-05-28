#ifndef CLIENT_CONNECTION_H
#define CLIENT_CONNECTION_H

#include "net.h"

struct client_connection {
	pool_t pool;

	int fd;
	struct io *io;
	struct istream *input;
	struct ostream *output;
	struct ssl_iostream *ssl_iostream;
	struct ip_addr local_ip, remote_ip;
	unsigned int local_port, remote_port;
	const struct doveadm_settings *set;

	unsigned int handshaked:1;
	unsigned int authenticated:1;
};

struct client_connection *
client_connection_create(int fd, int listen_fd, bool ssl);
void client_connection_destroy(struct client_connection **conn);

struct ostream *client_connection_get_output(struct client_connection *conn);

#endif
