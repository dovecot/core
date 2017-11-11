#ifndef CLIENT_AUTHENTICATE_H
#define CLIENT_AUTHENTICATE_H

void submission_client_auth_result(struct client *client,
				   enum client_auth_result result,
				   const struct client_auth_reply *reply,
				   const char *text);

void submission_client_auth_send_challenge(struct client *client,
					   const char *data);

int cmd_helo(void *conn_ctx, struct smtp_server_cmd_ctx *cmd,
	     struct smtp_server_cmd_helo *data);
int cmd_auth_continue(void *conn_ctx, struct smtp_server_cmd_ctx *cmd,
		      const char *response);
int cmd_auth(void *conn_ctx, struct smtp_server_cmd_ctx *cmd,
	     struct smtp_server_cmd_auth *data);

#endif
