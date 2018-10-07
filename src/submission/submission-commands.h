#ifndef SUBMISSION_COMMANDS_H
#define SUBMISSION_COMMANDS_H

/*
 * HELO command
 */

void submission_helo_reply_submit(struct smtp_server_cmd_ctx *cmd,
				  struct smtp_server_cmd_helo *data);

int cmd_helo(void *conn_ctx, struct smtp_server_cmd_ctx *cmd,
	     struct smtp_server_cmd_helo *data);

int client_default_cmd_helo(struct client *client,
			    struct smtp_server_cmd_ctx *cmd,
			    struct smtp_server_cmd_helo *data);

/*
 * MAIL command
 */

int cmd_mail(void *conn_ctx, struct smtp_server_cmd_ctx *cmd,
	     struct smtp_server_cmd_mail *data);

int client_default_cmd_mail(struct client *client,
			    struct smtp_server_cmd_ctx *cmd,
			    struct smtp_server_cmd_mail *data);

/*
 * RCPT command
 */

int cmd_rcpt(void *conn_ctx, struct smtp_server_cmd_ctx *cmd,
	     struct smtp_server_recipient *rcpt);

int client_default_cmd_rcpt(struct client *client ATTR_UNUSED,
			    struct submission_recipient *srcpt,
			    struct smtp_server_cmd_ctx *cmd,
			    struct smtp_server_recipient *rcpt);

/*
 * RSET command
 */

int cmd_rset(void *conn_ctx, struct smtp_server_cmd_ctx *cmd);

int client_default_cmd_rset(struct client *client,
			    struct smtp_server_cmd_ctx *cmd);

/*
 * DATA/BDAT commands
 */

int cmd_data_begin(void *conn_ctx, struct smtp_server_cmd_ctx *cmd,
		   struct smtp_server_transaction *trans,
		   struct istream *data_input);
int cmd_data_continue(void *conn_ctx, struct smtp_server_cmd_ctx *cmd,
		      struct smtp_server_transaction *trans);

int client_default_cmd_data(struct client *client,
			    struct smtp_server_cmd_ctx *cmd,
			    struct smtp_server_transaction *trans,
			    struct istream *data_input, uoff_t data_size);

/*
 * BURL command
 */

void cmd_burl(struct smtp_server_cmd_ctx *cmd, const char *params);

/*
 * VRFY command
 */

int cmd_vrfy(void *conn_ctx, struct smtp_server_cmd_ctx *cmd,
	     const char *param);

int client_default_cmd_vrfy(struct client *client,
			    struct smtp_server_cmd_ctx *cmd, const char *param);

/*
 * NOOP command
 */

int cmd_noop(void *conn_ctx, struct smtp_server_cmd_ctx *cmd);

int client_default_cmd_noop(struct client *client,
			    struct smtp_server_cmd_ctx *cmd);

/*
 * QUIT command
 */

int cmd_quit(void *conn_ctx, struct smtp_server_cmd_ctx *cmd);

int client_default_cmd_quit(struct client *client,
			    struct smtp_server_cmd_ctx *cmd);

#endif
