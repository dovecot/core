/* Copyright (c) 2018 Dovecot authors, see the included COPYING file */

#include "submission-common.h"
#include "str.h"
#include "mail-user.h"
#include "smtp-client.h"
#include "smtp-client-connection.h"
#include "smtp-client-command.h"

#include "submission-commands.h"
#include "submission-backend-relay.h"

/*
 * Common
 */

/* The command handling of the submission proxy service aims to follow the
   following rules:

   - Attempt to keep pipelined commands pipelined when proxying them to the
     actual relay service.
   - Don't forward commands if they're known to fail at the relay server. Errors
     can still occur if pipelined commands fail. Abort subsequent pending
     commands if such failures affect those commands.
   - Keep predictable errors consistent as much as possible; send our own reply
     if the error condition is clear (e.g. missing MAIL, RCPT).
*/

bool client_command_handle_proxy_reply(struct client *client,
	const struct smtp_reply *reply, struct smtp_reply *reply_r)
{
	*reply_r = *reply;

	switch (reply->status) {
	case SMTP_CLIENT_COMMAND_ERROR_ABORTED:
		return FALSE;
	case SMTP_CLIENT_COMMAND_ERROR_HOST_LOOKUP_FAILED:
	case SMTP_CLIENT_COMMAND_ERROR_CONNECT_FAILED:
	case SMTP_CLIENT_COMMAND_ERROR_AUTH_FAILED:
		i_unreached();
		return FALSE;
	case SMTP_CLIENT_COMMAND_ERROR_CONNECTION_CLOSED:
	case SMTP_CLIENT_COMMAND_ERROR_CONNECTION_LOST:
	case SMTP_CLIENT_COMMAND_ERROR_BAD_REPLY:
	case SMTP_CLIENT_COMMAND_ERROR_TIMED_OUT:
		client_destroy(client,
			"4.4.0", "Lost connection to relay server");
		return FALSE;
	/* RFC 4954, Section 6: 530 5.7.0 Authentication required

	   This response SHOULD be returned by any command other than AUTH,
	   EHLO, HELO, NOOP, RSET, or QUIT when server policy requires
	   authentication in order to perform the requested action and
	   authentication is not currently in force. */
	case 530:
		i_error("Relay server requires authentication: %s",
			smtp_reply_log(reply));
		client_destroy(client, "4.3.5",
			"Internal error occurred. "
			"Refer to server log for more information.");
		return FALSE;
	default:
		break;
	}

	if (!smtp_reply_has_enhanced_code(reply)) {
		reply_r->enhanced_code =
			SMTP_REPLY_ENH_CODE(reply->status / 100, 0, 0);
	}
	return TRUE;
}

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

int cmd_mail_relay(struct client *client, struct smtp_server_cmd_ctx *cmd,
		   struct smtp_server_cmd_mail *data)
{
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
