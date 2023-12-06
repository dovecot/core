#ifndef CLIENT_CONNECTION_H
#define CLIENT_CONNECTION_H

#include "net.h"

struct http_server;
#define DOVEADM_LOG_CHANNEL_ID 'L'

struct client_connection {
	pool_t pool;
	struct event *event;
	enum doveadm_client_type type;
	const char *name;

	struct ip_addr local_ip, remote_ip;
	in_port_t local_port, remote_port;

	const struct doveadm_settings *set;

	void (*free)(struct client_connection *conn);
};

extern struct client_connection *doveadm_client;

struct client_connection *
client_connection_tcp_create(int fd, int listen_fd, bool ssl);
struct client_connection *
client_connection_http_create(struct http_server *doveadm_http_server,
			      int fd, bool ssl);

#endif
