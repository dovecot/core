/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "submission-common.h"
#include "str.h"
#include "mail-user.h"
#include "smtp-syntax.h"
#include "smtp-address.h"
#include "smtp-client.h"
#include "smtp-client-connection.h"

#include "submission-commands.h"

/*
 * MAIL command
 */

struct cmd_mail_context {
	struct client *client;
	struct smtp_server_cmd_ctx *cmd;
	struct smtp_server_cmd_mail *data;

	struct smtp_client_command *cmd_proxied;
};

static void cmd_mail_update_xclient(struct client *client)
{
	struct smtp_proxy_data proxy_data;
	struct smtp_server_helo_data *helo_data =
		smtp_server_connection_get_helo_data(client->conn);

	if (client->xclient_sent)
		return;
	if (!client->set->submission_relay_trusted)
		return;
	if (helo_data->domain == NULL)
		return;

	i_zero(&proxy_data);
	proxy_data.helo = helo_data->domain;
	proxy_data.proto = SMTP_PROXY_PROTOCOL_ESMTP;

	(void)smtp_client_connection_send_xclient(
		client->proxy_conn, &proxy_data);
	client->xclient_sent = TRUE;
}

static void
cmd_mail_replied(struct smtp_server_cmd_ctx *cmd ATTR_UNUSED,
		 struct cmd_mail_context *mail_cmd)
{
	if (mail_cmd->cmd_proxied != NULL)
		smtp_client_command_abort(&mail_cmd->cmd_proxied);
}

static void cmd_mail_proxy_cb(const struct smtp_reply *proxy_reply,
			      struct cmd_mail_context *mail_cmd)
{
	struct smtp_server_cmd_ctx *cmd = mail_cmd->cmd;
	struct client *client = mail_cmd->client;
	struct smtp_reply reply;

	/* finished proxying MAIL command to relay server */
	i_assert(mail_cmd != NULL);
	mail_cmd->cmd_proxied = NULL;

	if (!client_command_handle_proxy_reply(client, proxy_reply, &reply))
		return;

	if ((proxy_reply->status / 100) == 2) {
		/* if relay accepts it, we accept it too */

		/* the default 2.0.0 code won't do */
		if (!smtp_reply_has_enhanced_code(proxy_reply))
			reply.enhanced_code = SMTP_REPLY_ENH_CODE(2, 1, 0);
	}

	/* forward reply */
	smtp_server_reply_forward(cmd, &reply);
}

static int
cmd_mail_parameter_auth(struct client *client,
			struct smtp_server_cmd_ctx *cmd,
			enum smtp_capability proxy_caps,
			struct smtp_server_cmd_mail *data)
{
	struct smtp_params_mail *params = &data->params;
	struct smtp_address *auth_addr;
	const char *error;

	if ((proxy_caps & SMTP_CAPABILITY_AUTH) == 0)
		return 0;

	auth_addr = NULL;
	if (smtp_address_parse_username(cmd->pool,
		client->user->username,
		&auth_addr, &error) < 0) {
		i_warning("Username `%s' is not a valid SMTP address: %s",
			client->user->username, error);
	}

	params->auth = auth_addr;
	return 0;
}

static int
cmd_mail_parameter_size(struct client *client,
			struct smtp_server_cmd_ctx *cmd,
			enum smtp_capability proxy_caps,
			struct smtp_server_cmd_mail *data)
{
	uoff_t max_size;

	/* SIZE=<size-value>: RFC 1870 */

	if (data->params.size == 0 || (proxy_caps & SMTP_CAPABILITY_SIZE) == 0)
		return 0;

	/* determine actual size limit (account for our additions) */
	max_size = client_get_max_mail_size(client);
	if (max_size > 0 && data->params.size > max_size) {
		smtp_server_reply(cmd, 552, "5.3.4",
			"Message size exceeds fixed maximum message size");
		return -1;
	}

	/* proxy the SIZE parameter (account for additional size) */
	data->params.size += SUBMISSION_MAX_ADDITIONAL_MAIL_SIZE;
	return 0;
}

int cmd_mail(void *conn_ctx, struct smtp_server_cmd_ctx *cmd,
	     struct smtp_server_cmd_mail *data)
{
	struct client *client = conn_ctx;
	struct cmd_mail_context *mail_cmd;
	enum smtp_capability proxy_caps =
		smtp_client_connection_get_capabilities(client->proxy_conn);

	/* check and adjust parameters where necessary */
	if (cmd_mail_parameter_auth(client, cmd, proxy_caps, data) < 0)
		return -1;
	if (cmd_mail_parameter_size(client, cmd, proxy_caps, data) < 0)
		return -1;

	cmd_mail_update_xclient(client);

	/* queue command (pipeline) */
	mail_cmd = p_new(cmd->pool, struct cmd_mail_context, 1);
	mail_cmd->cmd = cmd;
	mail_cmd->data = data;
	mail_cmd->client = client;

	smtp_server_command_add_hook(cmd->cmd, SMTP_SERVER_COMMAND_HOOK_REPLIED,
				     cmd_mail_replied, mail_cmd);

	mail_cmd->cmd_proxied = smtp_client_command_mail_submit(
		client->proxy_conn, 0, data->path, &data->params,
		cmd_mail_proxy_cb, mail_cmd);
	return 0;
}
