#ifndef __CLIENT_COMMON_H
#define __CLIENT_COMMON_H

#include "network.h"

struct client {
	struct ip_addr ip;
	int fd;

	master_callback_t *master_callback;
	/* ... */
};

struct client *client_create(int fd, struct ip_addr *ip, int ssl);

unsigned int clients_get_count(void);
void clients_destroy_all(void);

void clients_init(void);
void clients_deinit(void);

#endif
