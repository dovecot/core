#ifndef DOVEADM_SERVER_H
#define DOVEADM_SERVER_H

#define DOVEADM_PRINT_TYPE_SERVER "server"

extern struct client_connection *doveadm_client;
extern struct doveadm_print_vfuncs doveadm_print_server_vfuncs;

struct doveadm_server {
	const char *name;

	ARRAY_DEFINE(connections, struct server_connection *);
	ARRAY_TYPE(string) queue;
};

#endif
