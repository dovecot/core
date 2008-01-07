#ifndef CLIENT_COMMON_H
#define CLIENT_COMMON_H

#include "network.h"
#include "master.h"
#include "sasl-server.h"

struct client {
	struct client *prev, *next;

	struct ip_addr local_ip;
	struct ip_addr ip;
	unsigned int local_port, remote_port;
	struct ssl_proxy *proxy;

	int fd;

	char *auth_mech_name;
	struct auth_request *auth_request;

	unsigned int master_tag;
	master_callback_t *master_callback;
	sasl_server_callback_t *sasl_callback;

	unsigned int auth_attempts;

	char *virtual_user;
	unsigned int tls:1;
	unsigned int secured:1;
	unsigned int authenticating:1;
	unsigned int auth_tried_disabled_plaintext:1;
	/* ... */
};

extern struct client *clients;

struct client *client_create(int fd, bool ssl, const struct ip_addr *local_ip,
			     const struct ip_addr *ip);

void client_link(struct client *client);
void client_unlink(struct client *client);
unsigned int clients_get_count(void);

void client_syslog(struct client *client, const char *msg);

void clients_notify_auth_connected(void);
void client_destroy_oldest(void);
void clients_destroy_all(void);

void clients_init(void);
void clients_deinit(void);

#endif
