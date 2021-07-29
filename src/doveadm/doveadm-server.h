#ifndef DOVEADM_SERVER_H
#define DOVEADM_SERVER_H

#include "auth-proxy.h"

extern struct client_connection *doveadm_client;
extern struct doveadm_print_vfuncs doveadm_print_server_vfuncs;

struct doveadm_server {
	/* hostname:port or UNIX socket path. Used mainly for logging. */
	const char *name;
	/* If this contains '/', it's a UNIX socket path. Otherwise it's
	   the hostname without port. */
	const char *hostname;
	/* Host's IP to use, if known. Otherwise DNS lookup is done. */
	struct ip_addr ip;
	/* Port to use for TCP connections. */
	in_port_t port;

	const char *username, *password;

	/* ssl related settings */
	enum auth_proxy_ssl_flags ssl_flags;
	struct ssl_iostream_context *ssl_ctx;

	struct connection_list *connections;
	ARRAY_TYPE(string) queue;
};

#endif
