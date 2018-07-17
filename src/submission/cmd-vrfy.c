/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "submission-common.h"
#include "smtp-syntax.h"
#include "smtp-client.h"
#include "smtp-client-connection.h"

#include "submission-commands.h"

/*
 * VRFY command
 */

struct cmd_vrfy_context {
	struct client *client;
	struct smtp_server_cmd_ctx *cmd;
	struct smtp_client_command *cmd_proxied;
};

static void cmd_vrfy_proxy_cb(const struct smtp_reply *proxy_reply,
			      struct cmd_vrfy_context *vrfy_cmd)
{
	struct smtp_server_cmd_ctx *cmd = vrfy_cmd->cmd;
	struct client *client = vrfy_cmd->client;
	struct smtp_reply reply;

	if (!client_command_handle_proxy_reply(client, proxy_reply, &reply))
		return;

	if (!smtp_reply_has_enhanced_code(proxy_reply)) {
		switch (proxy_reply->status) {
		case 250:
		case 251:
		case 252:
			reply.enhanced_code = SMTP_REPLY_ENH_CODE(2, 5, 0);
			break;
		default:
			break;
		}
	}

	smtp_server_reply_forward(cmd, &reply);
}

int cmd_vrfy(void *conn_ctx, struct smtp_server_cmd_ctx *cmd,
	     const char *param)
{
	struct client *client = conn_ctx;
	struct cmd_vrfy_context *vrfy_cmd;

	vrfy_cmd = p_new(cmd->pool, struct cmd_vrfy_context, 1);
	vrfy_cmd->client = client;
	vrfy_cmd->cmd = cmd;

	vrfy_cmd->cmd_proxied = smtp_client_command_vrfy_submit(
		client->proxy_conn, 0, param, cmd_vrfy_proxy_cb, vrfy_cmd);
	return 0;
}
