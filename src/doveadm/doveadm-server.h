#ifndef DOVEADM_SERVER_H
#define DOVEADM_SERVER_H

#include "auth-proxy.h"

extern struct client_connection *doveadm_client;
extern struct doveadm_print_vfuncs doveadm_print_server_vfuncs;

struct doveadm_server {
	/* hostname:port or UNIX socket path. Used mainly for logging. */
	const char *name;
};

#endif
