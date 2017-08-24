#ifndef CLIENT_CONNECTION_H
#define CLIENT_CONNECTION_H

#include "net.h"

#define DOVEADM_LOG_CHANNEL_ID 'L'

struct client_connection {
	pool_t pool;

	int fd;
	const char *name;
	struct io *io;
	struct istream *input;
	struct ostream *output;
	struct ostream *log_out;
	struct ssl_iostream *ssl_iostream;
	struct ip_addr local_ip, remote_ip;
	in_port_t local_port, remote_port;
	const struct doveadm_settings *set;

	bool handshaked:1;
	bool authenticated:1;
	bool http:1;
	bool io_setup:1;
	bool use_multiplex:1;
};

struct client_connection *
client_connection_create(int fd, int listen_fd, bool ssl);
struct client_connection *
client_connection_create_http(int fd, bool ssl);
void client_connection_destroy(struct client_connection **conn);

#endif
