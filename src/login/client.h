#ifndef __CLIENT_H
#define __CLIENT_H

#include "network.h"

struct client {
	time_t created;
	int refcount;
	struct ip_addr ip;

	int fd;
	struct io *io;
	struct istream *input;
	struct ostream *output;

	time_t last_input;
	char *tag;

	buffer_t *plain_login;
	struct auth_request *auth_request;

	unsigned int tls:1;
};

struct client *client_create(int fd, struct ip_addr *ip, int imaps);
void client_destroy(struct client *client, const char *reason);

void client_ref(struct client *client);
int client_unref(struct client *client);

void client_send_line(struct client *client, const char *line);
void client_send_tagline(struct client *client, const char *line);
void client_syslog(struct client *client, const char *text);

int client_read(struct client *client);
void client_input(void *context, int fd, struct io *io);

unsigned int clients_get_count(void);
void clients_destroy_all(void);

void clients_init(void);
void clients_deinit(void);

#endif
