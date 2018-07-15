#ifndef SUBMISSION_BACKEND_RELAY_H
#define SUBMISSION_BACKEND_RELAY_H

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

#endif
