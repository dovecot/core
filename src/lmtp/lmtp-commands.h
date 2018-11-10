#ifndef COMMANDS_H
#define COMMANDS_H

struct client;
struct smtp_server_cmd_ctx;
struct smtp_server_cmd_helo;

/*
 * MAIL command
 */

int cmd_mail(void *conn_ctx, struct smtp_server_cmd_ctx *cmd,
	     struct smtp_server_cmd_mail *data);

int client_default_cmd_mail(struct client *client,
			    struct smtp_server_cmd_ctx *cmd ATTR_UNUSED,
			    struct smtp_server_cmd_mail *data ATTR_UNUSED);

/*
 * RCPT command
 */

int cmd_rcpt(void *conn_ctx, struct smtp_server_cmd_ctx *cmd,
	     struct smtp_server_recipient *rcpt);

int client_default_cmd_rcpt(struct client *client,
			    struct smtp_server_cmd_ctx *cmd,
			    struct lmtp_recipient *lrcpt);

/*
 * DATA command
 */

int cmd_data_continue(void *conn_ctx, struct smtp_server_cmd_ctx *cmd,
		      struct smtp_server_transaction *trans);
int cmd_data_begin(void *conn_ctx, struct smtp_server_cmd_ctx *cmd ATTR_UNUSED,
		   struct smtp_server_transaction *trans,
		   struct istream *data_input);

int client_default_cmd_data(struct client *client,
			    struct smtp_server_cmd_ctx *cmd,
			    struct smtp_server_transaction *trans,
			    struct istream *data_input, uoff_t data_size);

#endif
