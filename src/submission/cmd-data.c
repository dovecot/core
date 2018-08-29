/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "submission-common.h"
#include "str.h"
#include "str-sanitize.h"
#include "mail-storage.h"
#include "imap-url.h"
#include "imap-msgpart.h"
#include "imap-msgpart-url.h"
#include "imap-urlauth.h"
#include "imap-urlauth-fetch.h"
#include "smtp-address.h"
#include "smtp-client.h"
#include "smtp-client-connection.h"

#include "submission-commands.h"

/*
 * DATA/BDAT commands
 */

struct cmd_data_context {
	struct client *client;
	struct smtp_server_cmd_ctx *cmd;
	struct smtp_server_transaction *trans;

	struct smtp_client_command *cmd_proxied;
};

static void cmd_data_proxy_cb(const struct smtp_reply *proxy_reply,
			      struct cmd_data_context *data_ctx)
{
	struct smtp_server_cmd_ctx *cmd = data_ctx->cmd;
	struct smtp_server_transaction *trans = data_ctx->trans;
	struct client *client = data_ctx->client;
	struct smtp_reply reply;

	/* finished proxying message to relay server */

	/* check for fatal problems */
	if (!client_command_handle_proxy_reply(client, proxy_reply, &reply))
		return;

	if (proxy_reply->status / 100 == 2) {
		i_info("Successfully relayed message: "
		       "from=<%s>, size=%"PRIuUOFF_T", "
		       "id=%s, nrcpt=%u, reply=`%s'",
		       smtp_address_encode(trans->mail_from),
		       client->state.data_size, trans->id,
		       array_count(&trans->rcpt_to),
		       str_sanitize(smtp_reply_log(proxy_reply), 128));

	} else {
		i_info("Failed to relay message: "
		       "from=<%s>, size=%"PRIuUOFF_T", nrcpt=%u, reply=`%s'",
		       smtp_address_encode(trans->mail_from),
		       client->state.data_size, array_count(&trans->rcpt_to),
		       str_sanitize(smtp_reply_log(proxy_reply), 128));
	}

	smtp_server_reply_forward(cmd, &reply);
}

int cmd_data_relay(struct client *client, struct smtp_server_cmd_ctx *cmd,
		   struct smtp_server_transaction *trans,
		   struct istream *data_input)
{
	struct cmd_data_context *data_ctx;

	/* start relaying to relay server */
	data_ctx = p_new(trans->pool, struct cmd_data_context, 1);
	data_ctx->client = client;
	data_ctx->cmd = cmd;
	data_ctx->trans = trans;
	trans->context = (void*)data_ctx;

	data_ctx->cmd_proxied = smtp_client_command_data_submit(
		client->proxy_conn, 0, data_input, cmd_data_proxy_cb, data_ctx);
	return 0;
}

/*
 * BURL command
 */

/* FIXME: RFC 4468
   If the  URL argument to BURL refers to binary data, then the submit server
   MAY refuse the command or down convert as described in Binary SMTP.
 */

struct cmd_burl_context {
	struct client *client;
	struct smtp_server_cmd_ctx *cmd;

	struct imap_urlauth_fetch *urlauth_fetch;
	struct imap_msgpart_url *url_fetch;

	bool chunk_last:1;
};

static void
cmd_burl_destroy(struct smtp_server_cmd_ctx *cmd ATTR_UNUSED,
		 struct cmd_burl_context *burl_cmd)
{
	if (burl_cmd->urlauth_fetch != NULL)
		imap_urlauth_fetch_deinit(&burl_cmd->urlauth_fetch);
	if (burl_cmd->url_fetch != NULL)
		imap_msgpart_url_free(&burl_cmd->url_fetch);
}

static int
cmd_burl_fetch_cb(struct imap_urlauth_fetch_reply *reply,
		  bool last, void *context)
{
	struct cmd_burl_context *burl_cmd = context;
	struct smtp_server_cmd_ctx *cmd = burl_cmd->cmd;
	int ret;

	i_assert(last);

	if (reply == NULL) {
		/* fatal failure */
		// FIXME: make this an internal error
		smtp_server_reply(cmd, 554, "5.6.6",
			"IMAP URLAUTH resolution failed");
		return -1;
	}
	if (!reply->succeeded) {
		/* URL fetch failed */
		if (reply->error != NULL) {
			smtp_server_reply(cmd, 554, "5.6.6",
				"IMAP URLAUTH resolution failed: %s",
				reply->error);
		} else {
			smtp_server_reply(cmd, 554, "5.6.6",
				"IMAP URLAUTH resolution failed");
		}
		return 1;
	}

	/* URL fetch succeeded */
	ret = smtp_server_connection_data_chunk_add(cmd,
		reply->input, reply->size, burl_cmd->chunk_last, FALSE);
	if (ret < 0)
		return -1;

	/* Command is likely not yet complete at this point, so return 0 */
	return 0;
}

static int
cmd_burl_fetch_trusted(struct cmd_burl_context *burl_cmd,
		       struct imap_url *imap_url)
{
	struct smtp_server_cmd_ctx *cmd = burl_cmd->cmd;
	struct client *client = burl_cmd->client;
	const char *host_name = client->set->imap_urlauth_host;
	in_port_t host_port = client->set->imap_urlauth_port;
	struct imap_msgpart_open_result result;
	const char *error;

	/* validate host */
	if (imap_url->host.name == NULL ||
		(strcmp(host_name, URL_HOST_ALLOW_ANY) != 0 &&
		  strcmp(imap_url->host.name, host_name) != 0)) {
		smtp_server_reply(cmd, 554, "5.6.6",
			"IMAP URL resolution failed: "
			"Inappropriate or missing host name");
		return -1;
	}

	/* validate port */
	if ((imap_url->port == 0 && host_port != 143) ||
		(imap_url->port != 0 && host_port != imap_url->port)) {
		smtp_server_reply(cmd, 554, "5.6.6",
			"IMAP URL resolution failed: "
			"Inappropriate server port");
		return -1;
	}

	/* retrieve URL */
	if (imap_msgpart_url_create
		(client->user, imap_url, &burl_cmd->url_fetch, &error) < 0) {
		smtp_server_reply(cmd, 554, "5.6.6",
			"IMAP URL resolution failed: %s", error);
		return -1;
	}
	if (imap_msgpart_url_read_part(burl_cmd->url_fetch,
		&result, &error) <= 0) {
		smtp_server_reply(cmd, 554, "5.6.6",
			"IMAP URL resolution failed: %s", error);
		return -1;
	}

	return smtp_server_connection_data_chunk_add(cmd,
		result.input, result.size, burl_cmd->chunk_last, FALSE);
}

static int
cmd_burl_fetch(struct cmd_burl_context *burl_cmd, const char *url,
	       struct imap_url *imap_url)
{
	struct smtp_server_cmd_ctx *cmd = burl_cmd->cmd;
	struct client *client = burl_cmd->client;

	if (client->urlauth_ctx == NULL) {
		/* RFC5248, Section 2.4:

		   554 5.7.14 Trust relationship required

		   The submission server requires a configured trust
		   relationship with a third-party server in order to access
		   the message content. This value replaces the prior use of
		   X.7.8 for this error condition, thereby updating [RFC4468].
		 */
		smtp_server_reply(cmd, 554, "5.7.14",
			"No IMAP URLAUTH access available");
		return -1;
	}

	/* urlauth */
	burl_cmd->urlauth_fetch =
		imap_urlauth_fetch_init(client->urlauth_ctx,
					cmd_burl_fetch_cb, burl_cmd);
	if (imap_urlauth_fetch_url_parsed(burl_cmd->urlauth_fetch,
		url, imap_url, IMAP_URLAUTH_FETCH_FLAG_BODY) == 0) {
		/* wait for URL fetch */
		return 0;
	}
	return 1;
}

void cmd_burl(struct smtp_server_cmd_ctx *cmd, const char *params)
{
	struct smtp_server_connection *conn = cmd->conn;
	struct client *client = smtp_server_connection_get_context(conn);
	struct cmd_burl_context *burl_cmd;
	const char *const *argv;
	enum imap_url_parse_flags url_parse_flags =
		IMAP_URL_PARSE_ALLOW_URLAUTH;
	struct imap_url *imap_url;
	const char *url, *error;
	bool chunk_last = FALSE;
	int ret = 1;

	smtp_server_connection_data_chunk_init(cmd);

	/* burl-cmd   = "BURL" SP absolute-URI [SP end-marker] CRLF
	   end-marker = "LAST"
	 */
	argv = t_strsplit(params, " ");
	url = argv[0];
	if (url == NULL) {
		smtp_server_reply(cmd, 501, "5.5.4",
			"Missing chunk URL parameter");
		ret = -1;
	} else if (imap_url_parse(url, NULL, url_parse_flags,
				  &imap_url, &error) < 0) {
		smtp_server_reply(cmd, 501, "5.5.4",
			"Invalid chunk URL: %s", error);
		ret = -1;
	} else if (argv[1] != NULL) {
		if (strcasecmp(argv[1], "LAST") != 0) {
			smtp_server_reply(cmd, 501, "5.5.4",
				"Invalid end marker parameter");
			ret = -1;
		} else if (argv[2] != NULL) {
			smtp_server_reply(cmd, 501, "5.5.4",
				"Invalid parameters");
			ret = -1;
		} else {
			chunk_last = TRUE;
		}
	}

	if (ret < 0 || !smtp_server_connection_data_check_state(cmd))
		return;

	burl_cmd = p_new(cmd->pool, struct cmd_burl_context, 1);
	burl_cmd->client = client;
	burl_cmd->cmd = cmd;
	burl_cmd->chunk_last = chunk_last;

	smtp_server_command_add_hook(cmd->cmd, SMTP_SERVER_COMMAND_HOOK_DESTROY,
				     cmd_burl_destroy, burl_cmd);

	if (imap_url->uauth_rumpurl == NULL) {
		/* direct local url */
		ret = cmd_burl_fetch_trusted(burl_cmd, imap_url);
	} else {
		ret = cmd_burl_fetch(burl_cmd, url, imap_url);
	}

	if (ret == 0 && chunk_last)
		smtp_server_command_input_lock(cmd);
}
