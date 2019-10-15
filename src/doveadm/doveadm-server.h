#ifndef DOVEADM_SERVER_H
#define DOVEADM_SERVER_H

extern struct client_connection *doveadm_client;
extern struct doveadm_print_vfuncs doveadm_print_server_vfuncs;

enum doveadm_proxy_ssl_flags {
	/* Use SSL/TLS enabled */
	PROXY_SSL_FLAG_YES	= 0x01,
	/* Don't do SSL handshake immediately after connected */
	PROXY_SSL_FLAG_STARTTLS	= 0x02,
	/* Don't require that the received certificate is valid */
	PROXY_SSL_FLAG_ANY_CERT	= 0x04
};

struct doveadm_server {
	/* hostname:port or socket name for logging */
	const char *name;
	/* hostname without port */
	const char *hostname;
	/* host ip to use */
	struct ip_addr ip;
	/* port to use */
	in_port_t port;

	/* ssl related settings */
	enum doveadm_proxy_ssl_flags ssl_flags;
	struct ssl_iostream_context *ssl_ctx;

	ARRAY(struct server_connection *) connections;
	ARRAY_TYPE(string) queue;
};

#endif
