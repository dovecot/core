#ifndef COMMANDS_H
#define COMMANDS_H

struct client;
struct smtp_server_cmd_ctx;
struct smtp_server_cmd_helo;

int cmd_mail(void *conn_ctx, struct smtp_server_cmd_ctx *cmd,
	     struct smtp_server_cmd_mail *data);
int cmd_rcpt(void *conn_ctx, struct smtp_server_cmd_ctx *cmd,
	     struct smtp_server_cmd_rcpt *data);
int cmd_data_continue(void *conn_ctx, struct smtp_server_cmd_ctx *cmd,
		      struct smtp_server_transaction *trans);
int cmd_data_begin(void *conn_ctx, struct smtp_server_cmd_ctx *cmd ATTR_UNUSED,
		   struct smtp_server_transaction *trans,
		   struct istream *data_input);

#endif
