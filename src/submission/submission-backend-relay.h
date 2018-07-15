#ifndef SUBMISSION_BACKEND_RELAY_H
#define SUBMISSION_BACKEND_RELAY_H

#include "submission-backend.h"

struct client;

int cmd_helo_relay(struct client *client, struct smtp_server_cmd_ctx *cmd,
		   struct smtp_server_cmd_helo *data);
int cmd_mail_relay(struct client *client, struct smtp_server_cmd_ctx *cmd,
		   struct smtp_server_cmd_mail *data);
int cmd_rcpt_relay(struct client *client, struct smtp_server_cmd_ctx *cmd,
		   struct smtp_server_cmd_rcpt *data);
int cmd_rset_relay(struct client *client, struct smtp_server_cmd_ctx *cmd);
int cmd_data_relay(struct client *client, struct smtp_server_cmd_ctx *cmd,
		   struct smtp_server_transaction *trans,
		   struct istream *data_input);
int cmd_vrfy_relay(struct client *client, struct smtp_server_cmd_ctx *cmd,
		   const char *param);
int cmd_noop_relay(struct client *client, struct smtp_server_cmd_ctx *cmd);
int cmd_quit_relay(struct client *client, struct smtp_server_cmd_ctx *cmd);

struct submission_settings;

struct submission_backend_relay {
	struct submission_backend backend;

	struct smtp_client_connection *conn;

	bool xclient_sent:1;
};

void client_proxy_create(struct client *client,
			 const struct submission_settings *set);
void client_proxy_destroy(struct client *client);
void client_proxy_start(struct client *client);

void client_proxy_input_pre(struct client *client);
void client_proxy_input_post(struct client *client);

uoff_t client_proxy_get_max_mail_size(struct client *client);

#endif
