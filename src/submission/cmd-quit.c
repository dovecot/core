/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "submission-common.h"
#include "smtp-client.h"
#include "smtp-client-connection.h"

#include "submission-commands.h"

/*
 * QUIT command
 */

struct cmd_quit_context {
	struct client *client;
	struct smtp_server_cmd_ctx *cmd;
	struct smtp_client_command *cmd_proxied;
};

static void cmd_quit_proxy_cb(
	const struct smtp_reply *proxy_reply ATTR_UNUSED,
	struct cmd_quit_context *quit_cmd)
{
	struct smtp_server_cmd_ctx *cmd = quit_cmd->cmd;

	smtp_server_reply_quit(cmd);
}

int cmd_quit(void *conn_ctx, struct smtp_server_cmd_ctx *cmd)
{
	struct client *client = conn_ctx;
	struct cmd_quit_context *quit_cmd;

	quit_cmd = p_new(cmd->pool, struct cmd_quit_context, 1);
	quit_cmd->client = client;
	quit_cmd->cmd = cmd;
	cmd->context = quit_cmd;

	quit_cmd->cmd_proxied = smtp_client_command_new
		(client->proxy_conn, 0, cmd_quit_proxy_cb, quit_cmd);
	smtp_client_command_write(quit_cmd->cmd_proxied, "QUIT");
	smtp_client_command_submit(quit_cmd->cmd_proxied); // FIXME: timeout
	return 0;
}
