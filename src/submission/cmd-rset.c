/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "submission-common.h"
#include "smtp-client.h"
#include "smtp-client-connection.h"

#include "submission-commands.h"

/*
 * RSET command
 */

struct cmd_rset_context {
	struct client *client;
	struct smtp_server_cmd_ctx *cmd;

	struct smtp_client_command *cmd_proxied;
};

static void cmd_rset_proxy_cb(const struct smtp_reply *proxy_reply,
			      struct cmd_rset_context *rset_cmd)
{
	struct smtp_server_cmd_ctx *cmd = rset_cmd->cmd;
	struct client *client = rset_cmd->client;
	struct smtp_reply reply;

	/* finished proxying MAIL command to relay server */
	i_assert(rset_cmd != NULL);
	rset_cmd->cmd_proxied = NULL;

	if (!client_command_handle_proxy_reply(client, proxy_reply, &reply))
		return;

	/* forward reply */
	smtp_server_reply_forward(cmd, &reply);
}

int cmd_rset_relay(struct client *client, struct smtp_server_cmd_ctx *cmd)
{
	struct cmd_rset_context *rset_cmd;

	rset_cmd = p_new(cmd->pool, struct cmd_rset_context, 1);
	rset_cmd->cmd = cmd;
	rset_cmd->client = client;

	rset_cmd->cmd_proxied = smtp_client_command_rset_submit
		(client->proxy_conn, 0, cmd_rset_proxy_cb, rset_cmd);
	return 0;
}
