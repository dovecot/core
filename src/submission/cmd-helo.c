/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "submission-common.h"
#include "str.h"
#include "ostream.h"
#include "smtp-client.h"
#include "smtp-client-connection.h"

#include "submission-commands.h"

/*
 * EHLO, HELO commands
 */

struct cmd_helo_context {
	struct client *client;
	struct smtp_server_cmd_ctx *cmd;
	struct smtp_server_cmd_helo *data;

	struct smtp_client_command *cmd_proxied;
};

static void cmd_helo_update_xclient(struct client *client,
				    struct smtp_server_cmd_helo *data)
{
	struct smtp_proxy_data proxy_data;

	if (!client->set->submission_relay_trusted)
		return;

	i_zero(&proxy_data);
	proxy_data.helo = data->helo.domain;
	proxy_data.proto = (data->helo.old_smtp ?
		SMTP_PROXY_PROTOCOL_SMTP : SMTP_PROXY_PROTOCOL_ESMTP);

	(void)smtp_client_connection_send_xclient
		(client->proxy_conn, &proxy_data);
	client->xclient_sent = TRUE;
}

static void
cmd_helo_reply(struct smtp_server_cmd_ctx *cmd, struct cmd_helo_context *helo)
{
	struct client *client = helo->client;

	/* proxy an XCLIENT command */
	if (helo->data->changed)
		cmd_helo_update_xclient(client, helo->data);

	T_BEGIN {
		submission_helo_reply_submit(cmd, helo->data);
	} T_END;
}

static void cmd_helo_proxy_cb(const struct smtp_reply *proxy_reply,
			      struct cmd_helo_context *helo)
{
	struct smtp_server_cmd_ctx *cmd = helo->cmd;
	struct client *client = helo->client;
	struct smtp_reply reply;

	if (!client_command_handle_proxy_reply(client, proxy_reply, &reply))
		return;

	if ((proxy_reply->status / 100) == 2) {
		cmd_helo_reply(cmd, helo);
	} else {
		/* RFC 2034, Section 4:

		   These codes must appear in all 2xx, 4xx, and 5xx response
		   lines other than initial greeting and any response to HELO
		   or EHLO.
		 */
		reply.enhanced_code = SMTP_REPLY_ENH_CODE_NONE;
		smtp_server_reply_forward(cmd, &reply);
	}
}

static void
cmd_helo_start(struct smtp_server_cmd_ctx *cmd ATTR_UNUSED,
	       struct cmd_helo_context *helo)
{
	struct client *client = helo->client;

	/* proxy an XCLIENT command */
	if (helo->data->changed)
		cmd_helo_update_xclient(client, helo->data);
}

int cmd_helo_relay(struct client *client, struct smtp_server_cmd_ctx *cmd,
		   struct smtp_server_cmd_helo *data)
{
	struct cmd_helo_context *helo;

	helo = p_new(cmd->pool, struct cmd_helo_context, 1);
	helo->client = client;
	helo->cmd = cmd;
	helo->data = data;

	/* this is not the first HELO/EHLO; just proxy a RSET command */
	smtp_server_command_add_hook(
		cmd->cmd, SMTP_SERVER_COMMAND_HOOK_NEXT,
		cmd_helo_start, helo);
	helo->cmd_proxied = smtp_client_command_rset_submit
		(client->proxy_conn, 0, cmd_helo_proxy_cb, helo);
	return 0;
}

