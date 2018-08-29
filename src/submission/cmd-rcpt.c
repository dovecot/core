/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "submission-common.h"
#include "str.h"
#include "array.h"
#include "smtp-parser.h"
#include "smtp-address.h"
#include "smtp-syntax.h"
#include "smtp-client.h"
#include "smtp-client-connection.h"

#include "submission-commands.h"

/*
 * RCPT command
 */

struct cmd_rcpt_context {
	struct client *client;
	struct smtp_server_cmd_ctx *cmd;
	struct smtp_server_cmd_rcpt *data;

	struct smtp_client_command *cmd_proxied;
};

static void
cmd_rcpt_replied(struct smtp_server_cmd_ctx *cmd ATTR_UNUSED,
		 struct cmd_rcpt_context *rcpt_cmd)
{
	if (rcpt_cmd->cmd_proxied != NULL)
		smtp_client_command_abort(&rcpt_cmd->cmd_proxied);
}

static void cmd_rcpt_proxy_cb(const struct smtp_reply *proxy_reply,
			      struct cmd_rcpt_context *rcpt_cmd)
{
	struct smtp_server_cmd_ctx *cmd = rcpt_cmd->cmd;
	struct client *client = rcpt_cmd->client;
	struct smtp_reply reply;

	/* finished proxying MAIL command to relay server */
	i_assert(rcpt_cmd != NULL);
	rcpt_cmd->cmd_proxied = NULL;

	if (!client_command_handle_proxy_reply(client, proxy_reply, &reply))
		return;

	if ((proxy_reply->status / 100) == 2) {
		/* the default 2.0.0 code won't do */
		if (!smtp_reply_has_enhanced_code(proxy_reply))
			reply.enhanced_code = SMTP_REPLY_ENH_CODE(2, 1, 5);
	}

	/* forward reply */
	smtp_server_reply_forward(cmd, &reply);
}

int cmd_rcpt_relay(struct client *client, struct smtp_server_cmd_ctx *cmd,
		   struct smtp_server_cmd_rcpt *data)
{
	struct cmd_rcpt_context *rcpt_cmd;

	/* queue command (pipeline) */
	rcpt_cmd = p_new(cmd->pool, struct cmd_rcpt_context, 1);
	rcpt_cmd->cmd = cmd;
	rcpt_cmd->data = data;
	rcpt_cmd->client = client;

	smtp_server_command_add_hook(cmd->cmd, SMTP_SERVER_COMMAND_HOOK_REPLIED,
				     cmd_rcpt_replied, rcpt_cmd);

	rcpt_cmd->cmd_proxied = smtp_client_command_rcpt_submit(
		client->proxy_conn, 0, data->path, &data->params,
		cmd_rcpt_proxy_cb, rcpt_cmd);
	return 0;
}
