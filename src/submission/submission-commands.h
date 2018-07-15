#ifndef SUBMISSION_COMMANDS_H
#define SUBMISSION_COMMANDS_H

bool client_command_handle_proxy_reply(struct client *client,
	const struct smtp_reply *reply, struct smtp_reply *reply_r);

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

void submission_helo_reply_submit(struct smtp_server_cmd_ctx *cmd,
				  struct smtp_server_cmd_helo *data);
int cmd_helo(void *conn_ctx, struct smtp_server_cmd_ctx *cmd,
	     struct smtp_server_cmd_helo *data);

int cmd_mail(void *conn_ctx, struct smtp_server_cmd_ctx *cmd,
	     struct smtp_server_cmd_mail *data);
int cmd_rcpt(void *conn_ctx, struct smtp_server_cmd_ctx *cmd,
	     struct smtp_server_cmd_rcpt *data);
int cmd_rset(void *conn_ctx, struct smtp_server_cmd_ctx *cmd);

int cmd_data_begin(void *conn_ctx, struct smtp_server_cmd_ctx *cmd,
		   struct smtp_server_transaction *trans,
		   struct istream *data_input);
int cmd_data_continue(void *conn_ctx, struct smtp_server_cmd_ctx *cmd,
		      struct smtp_server_transaction *trans);
void cmd_burl(struct smtp_server_cmd_ctx *cmd, const char *params);

int cmd_vrfy(void *conn_ctx, struct smtp_server_cmd_ctx *cmd,
	     const char *param);

int cmd_noop(void *conn_ctx, struct smtp_server_cmd_ctx *cmd);
int cmd_quit(void *conn_ctx, struct smtp_server_cmd_ctx *cmd);

#endif
