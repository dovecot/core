/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream.h"
#include "ostream.h"
#include "iostream-ssl.h"
#include "master-service.h"
#include "master-service-ssl.h"
#include "smtp-syntax.h"

#include "smtp-server-private.h"

/* STARTTLS command (RFC 3207) */

static int cmd_starttls_start(struct smtp_server_connection *conn)
{
	const struct smtp_server_callbacks *callbacks = conn->callbacks;

	e_debug(conn->event, "Starting TLS");

	if (callbacks != NULL && callbacks->conn_start_tls != NULL) {
		struct smtp_server_connection *tmp_conn = conn;
		struct istream *input = conn->conn.input;
		struct ostream *output = conn->conn.output;
		int ret;

		smtp_server_connection_ref(tmp_conn);
		ret = callbacks->conn_start_tls(tmp_conn->context,
			&input, &output);
		if (!smtp_server_connection_unref(&tmp_conn) || ret < 0)
			return -1;

		smtp_server_connection_set_ssl_streams(conn, input, output);
	} else if (smtp_server_connection_ssl_init(conn) < 0) {
		smtp_server_connection_close(&conn,
			"SSL Initialization failed");
		return -1;
	}

	/* RFC 3207, Section 4.2:

	   Upon completion of the TLS handshake, the SMTP protocol is reset to
	   the initial state (the state in SMTP after a server issues a 220
	   service ready greeting). The server MUST discard any knowledge
	   obtained from the client, such as the argument to the EHLO command,
	   which was not obtained from the TLS negotiation itself.
	*/
	smtp_server_connection_clear(conn);
	smtp_server_connection_input_unlock(conn);

	return 0;
}

static int cmd_starttls_output(struct smtp_server_connection *conn)
{
	int ret;

	if ((ret=smtp_server_connection_flush(conn)) < 0)
		return 1;

	if (ret > 0) {
		o_stream_unset_flush_callback(conn->conn.output);
		if (cmd_starttls_start(conn) < 0)
			return -1;
	}
	return 1;
}

static void
cmd_starttls_destroy(struct smtp_server_cmd_ctx *cmd, void *context ATTR_UNUSED)
{
	struct smtp_server_connection *conn = cmd->conn;
	struct smtp_server_command *command = cmd->cmd;
	int ret;

	if (conn->conn.output == NULL)
		return;

	if (smtp_server_command_replied_success(command)) {
		/* only one valid success status for STARTTLS command */
		i_assert(smtp_server_command_reply_status_equals(command, 220));

		/* uncork */
		o_stream_uncork(conn->conn.output);

		/* flush */
		if ((ret=smtp_server_connection_flush(conn)) < 0) {
			return;
		} else if (ret == 0) {
			/* the buffer has to be flushed */
			i_assert(!conn->conn.output->closed);
			o_stream_set_flush_callback(conn->conn.output,
						    cmd_starttls_output,
						    conn);
			o_stream_set_flush_pending(conn->conn.output, TRUE);
		} else {
			cmd_starttls_start(conn);
		}
	}
}

static void
cmd_starttls_next(struct smtp_server_cmd_ctx *cmd, void *context ATTR_UNUSED)
{
	struct smtp_server_connection *conn = cmd->conn;
	struct smtp_server_command *command = cmd->cmd;
	const struct smtp_server_callbacks *callbacks = conn->callbacks;
	int ret;

	smtp_server_connection_set_state(conn, SMTP_SERVER_STATE_STARTTLS,
					 NULL);

	smtp_server_command_ref(command);
	if (callbacks != NULL && callbacks->conn_cmd_starttls != NULL)
		ret = callbacks->conn_cmd_starttls(conn->context, cmd);
	else
		ret = 1;

	smtp_server_command_add_hook(command, SMTP_SERVER_COMMAND_HOOK_DESTROY,
				     cmd_starttls_destroy, NULL);

	if (ret <= 0) {
		i_assert(ret == 0 || smtp_server_command_is_replied(command));
		/* command is waiting for external event or it failed */
		smtp_server_command_unref(&command);
		return;
	}
	if (!smtp_server_command_is_replied(command)) {
		smtp_server_reply(cmd,
			220, "2.0.0", "Begin TLS negotiation now.");
	}
	smtp_server_command_unref(&command);
}

void smtp_server_cmd_starttls(struct smtp_server_cmd_ctx *cmd,
			      const char *params)
{
	struct smtp_server_connection *conn = cmd->conn;
	struct smtp_server_command *command = cmd->cmd;
	enum smtp_capability capabilities = conn->set.capabilities;

	if (conn->ssl_secured) {
		i_assert((capabilities & SMTP_CAPABILITY_STARTTLS) == 0);
		smtp_server_reply(cmd,
			502, "5.5.1", "TLS is already active.");
		return;
	} else if ((capabilities & SMTP_CAPABILITY_STARTTLS) == 0) {
		smtp_server_reply(cmd,
			502, "5.5.1", "TLS support is not enabled.");
		return;
	}

	/* "STARTTLS" CRLF */
	if (*params != '\0') {
		smtp_server_reply(cmd,
			501, "5.5.4", "Invalid parameters");
		return;
	}

	smtp_server_command_input_lock(cmd);
	smtp_server_connection_input_lock(conn);

	smtp_server_command_add_hook(command, SMTP_SERVER_COMMAND_HOOK_NEXT,
				     cmd_starttls_next, NULL);
}
