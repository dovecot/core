#ifndef __CLIENT_H
#define __CLIENT_H

#include "network.h"

struct _Client {
	time_t created;
	int refcount;
	IPADDR ip;

	int fd;
	IO io;
	IStream *input;
	OStream *output;

	time_t last_input;
	char *tag;

	unsigned char *plain_login;
	unsigned int plain_login_len;

	AuthRequest *auth_request;

	unsigned int tls:1;
};

Client *client_create(int fd, IPADDR *ip, int imaps);
void client_destroy(Client *client, const char *reason);

void client_ref(Client *client);
int client_unref(Client *client);

void client_send_line(Client *client, const char *line);
void client_send_tagline(Client *client, const char *line);
void client_syslog(Client *client, const char *text);

int client_read(Client *client);
void client_input(void *context, int fd, IO io);

unsigned int clients_get_count(void);
void clients_destroy_all(void);

void clients_init(void);
void clients_deinit(void);

#endif
