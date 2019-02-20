/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream.h"
#include "smtp-syntax.h"
#include "smtp-command-parser.h"

#include "smtp-server-private.h"

/* AUTH command (RFC 4954) */


static bool
cmd_auth_check_state(struct smtp_server_cmd_ctx *cmd)
{
	struct smtp_server_connection *conn = cmd->conn;

	/* RFC 4954, Section 4:
	   After an AUTH command has been successfully completed, no more
	   AUTH commands may be issued in the same session.  After a
	   successful AUTH command completes, a server MUST reject any
	   further AUTH commands with a 503 reply. */
	if (conn->authenticated) {
		smtp_server_reply(cmd,
			503, "5.5.0", "Already authenticated");
		return FALSE;
	}

	/* RFC 4954, Section 4:
	   The AUTH command is not permitted during a mail transaction.
	   An AUTH command issued during a mail transaction MUST be
	   rejected with a 503 reply. */
	if (conn->state.trans != NULL) {
		smtp_server_reply(cmd, 503, "5.5.0",
			"Authentication not permitted during a mail transaction");
		return FALSE;
	}
	return TRUE;
}

void smtp_server_cmd_auth_success(struct smtp_server_cmd_ctx *cmd,
				  const char *username, const char *success_msg)
{
	cmd->conn->username = i_strdup(username);

	smtp_server_reply(cmd, 235, "2.7.0", "%s",
		(success_msg == NULL ? "Logged in." : success_msg));
}

static void
cmd_auth_completed(struct smtp_server_cmd_ctx *cmd,
		   struct smtp_server_cmd_auth *data ATTR_UNUSED)
{
	struct smtp_server_connection *conn = cmd->conn;
	struct smtp_server_command *command = cmd->cmd;

	i_assert(smtp_server_command_is_replied(command));
	if (smtp_server_command_replied_success(command)) {
		/* only one valid success status for AUTH command */
		i_assert(smtp_server_command_reply_status_equals(command, 235));
		conn->authenticated = TRUE;
	}
}

static void cmd_auth_input(struct smtp_server_cmd_ctx *cmd)
{
	struct smtp_server_connection *conn = cmd->conn;
	const struct smtp_server_callbacks *callbacks = conn->callbacks;
	struct smtp_server_command *command = cmd->cmd;
	enum smtp_command_parse_error error_code;
	const char *auth_response, *error;
	int ret;

	/* parse response */
	if ((ret=smtp_command_parse_auth_response(conn->smtp_parser,
		&auth_response, &error_code, &error)) <= 0) {
		/* check for disconnect */
		if (conn->conn.input->eof) {
			switch (conn->conn.input->stream_errno) {
			case 0:
			case EPIPE:
			case ECONNRESET:
				smtp_server_connection_close(&conn,
					"Remote closed connection unexpectedly during AUTH");
				break;
			default:
				smtp_server_connection_error(conn,
					"Connection lost during AUTH: "
					"read(%s) failed: %s",
					i_stream_get_name(conn->conn.input),
					i_stream_get_error(conn->conn.input));
				smtp_server_connection_close(&conn,
					"Read failure");
			}
			return;
		}
		/* handle syntax error */
		if (ret < 0) {
			smtp_server_connection_debug(conn,
				"Client sent invalid AUTH response: %s", error);

			switch (error_code) {
			case SMTP_COMMAND_PARSE_ERROR_BROKEN_COMMAND:
				conn->input_broken = TRUE;
				/* fall through */
			case SMTP_COMMAND_PARSE_ERROR_BAD_COMMAND:
				smtp_server_reply(cmd, 500, "5.5.2",
					"Invalid AUTH response syntax");
				break;
			case SMTP_COMMAND_PARSE_ERROR_LINE_TOO_LONG:
				smtp_server_reply(cmd, 500, "5.5.2",
					"Line too long");
				break;
			default:
				i_unreached();
			}
		}
		if (conn->input_broken || conn->closing)
			smtp_server_connection_input_halt(conn);
		return;
	}

	smtp_server_connection_debug(conn,
		"Received AUTH response: %s", auth_response);

	smtp_server_command_input_lock(cmd);

	/* continue authentication */
	smtp_server_command_ref(command);
	i_assert(callbacks != NULL &&
		 callbacks->conn_cmd_auth_continue != NULL);
	if ((ret=callbacks->conn_cmd_auth_continue(conn->context,
		cmd, auth_response)) <= 0) {
		/* command is waiting for external event or it failed */
		i_assert(ret == 0 || smtp_server_command_is_replied(command));
		smtp_server_command_unref(&command);
		return;
	}
	if (!smtp_server_command_is_replied(command)) {
		/* set generic AUTH success reply if none is provided */
		smtp_server_reply(cmd, 235, "2.7.0", "Logged in.");
	}
	conn->authenticated = TRUE;
	smtp_server_command_unref(&command);
}

void smtp_server_cmd_auth_send_challenge(struct smtp_server_cmd_ctx *cmd,
					 const char *challenge)
{
	struct smtp_server_connection *conn = cmd->conn;
	struct smtp_server_command *command = cmd->cmd;

	i_assert(command->prev == NULL &&
		command->reg->func == smtp_server_cmd_auth);

	smtp_server_connection_reply_immediate(conn, 334, "%s", challenge);
	smtp_server_connection_timeout_reset(conn);

	/* start AUTH-specific input handling */
	smtp_server_command_input_capture(cmd, cmd_auth_input);
}

static void
cmd_auth_start(struct smtp_server_cmd_ctx *cmd,
	       struct smtp_server_cmd_auth *data)
{
	struct smtp_server_connection *conn = cmd->conn;
	struct smtp_server_command *command = cmd->cmd;
	const struct smtp_server_callbacks *callbacks = conn->callbacks;
	int ret;

	/* all preceeding commands have finished and now the transaction state
	   is clear. This provides the opportunity to re-check the protocol
	   state */
	if (!cmd_auth_check_state(cmd))
		return;

	/* advance state */
	smtp_server_connection_set_state(conn, SMTP_SERVER_STATE_AUTH);

	smtp_server_command_ref(command);
	i_assert(callbacks != NULL && callbacks->conn_cmd_auth != NULL);

	/* specific implementation of AUTH command */
	ret = callbacks->conn_cmd_auth(conn->context, cmd, data);
	i_assert(ret == 0 || smtp_server_command_is_replied(command));

	if (ret == 0)
		smtp_server_connection_timeout_stop(conn);

	smtp_server_command_unref(&command);
	return;
}

void smtp_server_cmd_auth(struct smtp_server_cmd_ctx *cmd,
			  const char *params)
{
	struct smtp_server_connection *conn = cmd->conn;
	struct smtp_server_command *command = cmd->cmd;
	struct smtp_server_cmd_auth *auth_data;
	const char *sasl_mech, *initial_response;
	const char *const *argv;
	int ret = 1;

	if ((conn->set.capabilities & SMTP_CAPABILITY_AUTH) == 0) {
		smtp_server_reply(cmd,
			502, "5.5.1", "Unsupported command");
		return;
	}

	/* RFC 4954, Section 8:

	   auth-command     = "AUTH" SP sasl-mech [SP initial-response]
	                      *(CRLF [base64]) [CRLF cancel-response]
	                      CRLF
	                      ;; <sasl-mech> is defined in [SASL]

	   initial-response = base64 / "="
	 */
	argv = t_strsplit(params, " ");
	initial_response = sasl_mech = NULL;
	if (argv[0] == NULL) {
		smtp_server_reply(cmd,
			501, "5.5.4", "Missing SASL mechanism parameter");
		ret = -1;
	} else {
		sasl_mech = argv[0];

		if (argv[1] != NULL) {
			if (argv[2] != NULL) {
				smtp_server_reply(cmd,
					501, "5.5.4", "Invalid parameters");
				ret = -1;
			} else {
				initial_response = argv[1];
			}
		}
	}
	if (ret < 0)
		return;

	/* check protocol state */
	if (!cmd_auth_check_state(cmd))
		return;

	smtp_server_command_input_lock(cmd);

	auth_data = p_new(cmd->pool, struct smtp_server_cmd_auth, 1);
	auth_data->sasl_mech = p_strdup(cmd->pool, sasl_mech);
	auth_data->initial_response = p_strdup(cmd->pool, initial_response);

	smtp_server_command_add_hook(command, SMTP_SERVER_COMMAND_HOOK_NEXT,
				     cmd_auth_start, auth_data);
	smtp_server_command_add_hook(command, SMTP_SERVER_COMMAND_HOOK_COMPLETED,
				     cmd_auth_completed, auth_data);
}
