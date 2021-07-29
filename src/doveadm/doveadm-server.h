#ifndef DOVEADM_SERVER_H
#define DOVEADM_SERVER_H

#include "auth-proxy.h"

extern struct client_connection *doveadm_client;
extern struct doveadm_print_vfuncs doveadm_print_server_vfuncs;

struct doveadm_server {
	/* hostname:port or socket name for logging */
	const char *name;
	/* hostname without port */
	const char *hostname;
	/* host ip to use */
	struct ip_addr ip;
	/* port to use */
	in_port_t port;

	const char *username, *password;

	/* ssl related settings */
	enum auth_proxy_ssl_flags ssl_flags;
	struct ssl_iostream_context *ssl_ctx;

	ARRAY(struct server_connection *) connections;
	ARRAY_TYPE(string) queue;
};

#endif
