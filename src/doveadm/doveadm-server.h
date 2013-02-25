#ifndef DOVEADM_SERVER_H
#define DOVEADM_SERVER_H

#define DOVEADM_PRINT_TYPE_SERVER "server"

extern struct client_connection *doveadm_client;
extern struct doveadm_print_vfuncs doveadm_print_server_vfuncs;

struct doveadm_server {
	const char *name;
	struct ssl_iostream_context *ssl_ctx;

	ARRAY(struct server_connection *) connections;
	ARRAY_TYPE(string) queue;
};

#endif
