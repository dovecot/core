/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "submission-common.h"
#include "smtp-client.h"
#include "smtp-client-connection.h"

#include "submission-commands.h"

/*
 * NOOP command
 */

struct cmd_noop_context {
	struct client *client;
	struct smtp_server_cmd_ctx *cmd;
	struct smtp_client_command *cmd_proxied;
};

static void cmd_noop_proxy_cb(const struct smtp_reply *proxy_reply,
			      struct cmd_noop_context *noop_cmd)
{
	struct smtp_server_cmd_ctx *cmd = noop_cmd->cmd;
	struct client *client = noop_cmd->client;
	struct smtp_reply reply;

	if (!client_command_handle_proxy_reply(client, proxy_reply, &reply))
		return;

	if ((proxy_reply->status / 100) == 2) {
		smtp_server_reply(cmd, 250, "2.0.0", "OK");
	} else {
		smtp_server_reply_forward(cmd, &reply);
	}
}

int cmd_noop_relay(struct client *client, struct smtp_server_cmd_ctx *cmd)
{
	struct cmd_noop_context *noop_cmd;

	noop_cmd = p_new(cmd->pool, struct cmd_noop_context, 1);
	noop_cmd->client = client;
	noop_cmd->cmd = cmd;

	noop_cmd->cmd_proxied = smtp_client_command_noop_submit
		(client->proxy_conn, 0, cmd_noop_proxy_cb, noop_cmd);
	return 0;
}
