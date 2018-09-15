#ifndef SUBMISSION_BACKEND_RELAY_H
#define SUBMISSION_BACKEND_RELAY_H

#include "submission-backend.h"

struct client;

struct submission_settings;

struct submission_backend_relay {
	struct submission_backend backend;

	struct smtp_client_connection *conn;

	bool xclient_sent:1;
	bool started:1;
};

void client_proxy_create(struct client *client,
			 const struct submission_settings *set);
void client_proxy_start(struct client *client);

void client_proxy_input_pre(struct client *client);
void client_proxy_input_post(struct client *client);

uoff_t client_proxy_get_max_mail_size(struct client *client);

#endif
