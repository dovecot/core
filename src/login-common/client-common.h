#ifndef __CLIENT_COMMON_H
#define __CLIENT_COMMON_H

#include "network.h"
#include "master.h"

struct client {
	struct ip_addr local_ip;
	struct ip_addr ip;
	struct ssl_proxy *proxy;

	int fd;
	struct io *io;

	struct auth_request *auth_request;
	unsigned int master_tag;
	master_callback_t *master_callback;

	char *virtual_user;
	/* ... */
};

struct client *client_create(int fd, int ssl, const struct ip_addr *local_ip,
			     const struct ip_addr *ip);

unsigned int clients_get_count(void);
void clients_notify_auth_connected(void);
void clients_destroy_all(void);

void clients_init(void);
void clients_deinit(void);

#endif
