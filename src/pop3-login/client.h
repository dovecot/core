#ifndef __CLIENT_H
#define __CLIENT_H

#include "network.h"
#include "master.h"
#include "client-common.h"

struct pop3_client {
	struct client common;

	time_t created;
	int refcount;

	struct istream *input;
	struct ostream *output;

	time_t last_input;
	unsigned int bad_counter;

	buffer_t *plain_login;

	unsigned int tls:1;
};

struct client *client_create(int fd, struct ip_addr *ip, int ssl);
void client_destroy(struct pop3_client *client, const char *reason);

void client_ref(struct pop3_client *client);
int client_unref(struct pop3_client *client);

void client_send_line(struct pop3_client *client, const char *line);
void client_syslog(struct pop3_client *client, const char *text);

int client_read(struct pop3_client *client);
void client_input(void *context);

unsigned int clients_get_count(void);
void clients_destroy_all(void);

void clients_init(void);
void clients_deinit(void);

#endif
