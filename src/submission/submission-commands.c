/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "submission-common.h"
#include "str.h"
#include "istream.h"
#include "istream-concat.h"
#include "istream-seekable.h"
#include "mail-storage.h"
#include "smtp-client.h"
#include "smtp-client-connection.h"

#include "submission-commands.h"
#include "submission-backend-relay.h"

/*
 * EHLO, HELO commands
 */

void submission_helo_reply_submit(struct smtp_server_cmd_ctx *cmd,
				  struct smtp_server_cmd_helo *data)
{
	struct client *client = smtp_server_connection_get_context(cmd->conn);
	enum smtp_capability proxy_caps =
		smtp_client_connection_get_capabilities(client->proxy_conn);
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

int cmd_rcpt(void *conn_ctx, struct smtp_server_cmd_ctx *cmd,
	     struct smtp_server_cmd_rcpt *data)
{
	struct client *client = conn_ctx;

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

