/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "submission-common.h"
#include "str.h"
#include "istream.h"
#include "istream-concat.h"
#include "istream-seekable.h"
#include "mail-storage.h"
#include "imap-url.h"
#include "imap-msgpart.h"
#include "imap-msgpart-url.h"
#include "imap-urlauth.h"
#include "imap-urlauth-fetch.h"
#include "smtp-client.h"
#include "smtp-client-connection.h"

#include "submission-recipient.h"
#include "submission-commands.h"
#include "submission-backend-relay.h"

/*
 * EHLO, HELO commands
 */

void submission_helo_reply_submit(struct smtp_server_cmd_ctx *cmd,
				  struct smtp_server_cmd_helo *data)
{
	struct client *client = smtp_server_connection_get_context(cmd->conn);
	struct submission_backend_relay *backend = &client->backend;
	enum smtp_capability proxy_caps =
		smtp_client_connection_get_capabilities(backend->conn);
	struct smtp_server_reply *reply;
	uoff_t cap_size;

	reply = smtp_server_reply_create_ehlo(cmd->cmd);
	if (!data->helo.old_smtp) {
		string_t *burl_params = t_str_new(256);

		str_append(burl_params, "imap");
		if (*client->set->imap_urlauth_host == '\0' ||
			strcmp(client->set->imap_urlauth_host,
			       URL_HOST_ALLOW_ANY) == 0) {
			str_printfa(burl_params, " imap://%s",
				    client->set->hostname);
		} else {
			str_printfa(burl_params, " imap://%s",
				    client->set->imap_urlauth_host);
		}
		if (client->set->imap_urlauth_port != 143) {
			str_printfa(burl_params, ":%u",
				    client->set->imap_urlauth_port);
		}

		if ((proxy_caps & SMTP_CAPABILITY_8BITMIME) != 0)
			smtp_server_reply_ehlo_add(reply, "8BITMIME");
		smtp_server_reply_ehlo_add(reply, "AUTH");
		if ((proxy_caps & SMTP_CAPABILITY_BINARYMIME) != 0 &&
			(proxy_caps & SMTP_CAPABILITY_CHUNKING) != 0)
			smtp_server_reply_ehlo_add(reply, "BINARYMIME");
		smtp_server_reply_ehlo_add_param(reply,
			"BURL", "%s", str_c(burl_params));
		smtp_server_reply_ehlo_add(reply, "CHUNKING");
		if ((proxy_caps & SMTP_CAPABILITY_DSN) != 0)
			smtp_server_reply_ehlo_add(reply, "DSN");
		smtp_server_reply_ehlo_add(reply,
			"ENHANCEDSTATUSCODES");
		smtp_server_reply_ehlo_add(reply,
			"PIPELINING");

		cap_size = client_get_max_mail_size(client);
		if (cap_size > 0) {
			smtp_server_reply_ehlo_add_param(reply,
				"SIZE", "%"PRIuUOFF_T, cap_size);
		} else {
			smtp_server_reply_ehlo_add(reply, "SIZE");
		}
		smtp_server_reply_ehlo_add(reply, "VRFY");
	}
	smtp_server_reply_submit(reply);
}

int cmd_helo(void *conn_ctx, struct smtp_server_cmd_ctx *cmd,
	     struct smtp_server_cmd_helo *data)
{
	struct client *client = conn_ctx;

	if (!data->first ||
	    smtp_server_connection_get_state(client->conn)
		>= SMTP_SERVER_STATE_READY)
		return cmd_helo_relay(client, cmd, data);

	/* respond right away */
	submission_helo_reply_submit(cmd, data);
	return 1;
}

/*
 * MAIL command
 */

int cmd_mail(void *conn_ctx, struct smtp_server_cmd_ctx *cmd,
	     struct smtp_server_cmd_mail *data)
{
	struct client *client = conn_ctx;

	return cmd_mail_relay(client, cmd, data);
}

/*
 * RCPT command
 */

static void
cmd_rcpt_destroy(struct smtp_server_cmd_ctx *cmd ATTR_UNUSED,
		 struct submission_recipient *rcpt)
{
	submission_recipient_destroy(&rcpt);
}

static void
submission_rcpt_finished(struct smtp_server_cmd_ctx *cmd,
			 struct smtp_server_transaction *trans ATTR_UNUSED,
			 struct smtp_server_recipient *trcpt,
			 unsigned int index)
{
	struct submission_recipient *rcpt = trcpt->context;

	smtp_server_command_remove_hook(cmd->cmd,
					SMTP_SERVER_COMMAND_HOOK_DESTROY,
					cmd_rcpt_destroy);

	submission_recipient_finished(rcpt, trcpt, index);
}

int cmd_rcpt(void *conn_ctx, struct smtp_server_cmd_ctx *cmd,
	     struct smtp_server_cmd_rcpt *data)
{
	struct client *client = conn_ctx;
	struct submission_recipient *rcpt;

	rcpt = submission_recipient_create(client, data->path);

	smtp_server_command_add_hook(cmd->cmd, SMTP_SERVER_COMMAND_HOOK_DESTROY,
				     cmd_rcpt_destroy, rcpt);

	data->trans_context = rcpt;
	data->hook_finished = submission_rcpt_finished;

	return cmd_rcpt_relay(client, cmd, data);
}

/*
 * RSET command
 */

int cmd_rset(void *conn_ctx, struct smtp_server_cmd_ctx *cmd)
{
	struct client *client = conn_ctx;

	return cmd_rset_relay(client, cmd);
}

/*
 * DATA/BDAT commands
 */

int cmd_data_continue(void *conn_ctx, struct smtp_server_cmd_ctx *cmd,
		      struct smtp_server_transaction *trans)
{
	struct client *client = conn_ctx;
	struct istream *data_input = client->state.data_input;
	struct istream *inputs[3];
	string_t *added_headers;
	const unsigned char *data;
	size_t size;
	int ret;

	while ((ret = i_stream_read_more(data_input, &data, &size)) > 0) {
		i_stream_skip(data_input, size);
		if (!smtp_server_cmd_data_check_size(cmd))
			return -1;
	}

	if (ret == 0)
		return 0;
	if (ret < 0 && data_input->stream_errno != 0)
		return -1;

	/* Done reading DATA stream; remove it from state and continue with
	   local variable. */
	client->state.data_input = NULL;

	ret = i_stream_get_size(data_input, TRUE,
				&client->state.data_size);
	i_assert(ret > 0); // FIXME

	/* prepend our own headers */
	added_headers = t_str_new(200);
	smtp_server_transaction_write_trace_record(added_headers, trans);

	i_stream_seek(data_input, 0);
	inputs[0] = i_stream_create_copy_from_data(
		str_data(added_headers), str_len(added_headers));
	inputs[1] = data_input;
	inputs[2] = NULL;

	data_input = i_stream_create_concat(inputs);
	i_stream_unref(&inputs[0]);
	i_stream_unref(&inputs[1]);

	ret = cmd_data_relay(client, cmd, trans, data_input);

	i_stream_unref(&data_input);
	return ret;
}

int cmd_data_begin(void *conn_ctx,
		   struct smtp_server_cmd_ctx *cmd ATTR_UNUSED,
		   struct smtp_server_transaction *trans ATTR_UNUSED,
		   struct istream *data_input)
{
	struct client *client = conn_ctx;
	struct istream *inputs[2];
	string_t *path;

	inputs[0] = data_input;
	inputs[1] = NULL;

	path = t_str_new(256);
	mail_user_set_get_temp_prefix(path, client->user->set);
	client->state.data_input = i_stream_create_seekable_path(inputs,
		SUBMISSION_MAIL_DATA_MAX_INMEMORY_SIZE, str_c(path));
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

/*
 * VRFY command
 */

int cmd_vrfy(void *conn_ctx, struct smtp_server_cmd_ctx *cmd,
	     const char *param)
{
	struct client *client = conn_ctx;

	return cmd_vrfy_relay(client, cmd, param);
}

/*
 * NOOP command
 */

int cmd_noop(void *conn_ctx, struct smtp_server_cmd_ctx *cmd)
{
	struct client *client = conn_ctx;

	return cmd_noop_relay(client, cmd);
}

/*
 * QUIT command
 */

struct cmd_quit_context {
	struct client *client;

	struct smtp_server_cmd_ctx *cmd;
};

static void cmd_quit_finish(struct cmd_quit_context *quit_cmd)
{
	struct client *client = quit_cmd->client;
	struct smtp_server_cmd_ctx *cmd = quit_cmd->cmd;

	timeout_remove(&client->to_quit);
	smtp_server_reply_quit(cmd);
}

static void
cmd_quit_next(struct smtp_server_cmd_ctx *cmd ATTR_UNUSED,
	      struct cmd_quit_context *quit_cmd)
{
	struct client *client = quit_cmd->client;

	/* give backend a brief interval to generate a quit reply */
	client->to_quit = timeout_add(SUBMISSION_MAX_WAIT_QUIT_REPLY_MSECS,
				      cmd_quit_finish, quit_cmd);
}

int cmd_quit(void *conn_ctx, struct smtp_server_cmd_ctx *cmd)
{
	struct client *client = conn_ctx;
	struct cmd_quit_context *quit_cmd;

	quit_cmd = p_new(cmd->pool, struct cmd_quit_context, 1);
	quit_cmd->client = client;
	quit_cmd->cmd = cmd;

	smtp_server_command_add_hook(cmd->cmd, SMTP_SERVER_COMMAND_HOOK_NEXT,
				     cmd_quit_next, quit_cmd);

	return cmd_quit_relay(client, cmd);
}

