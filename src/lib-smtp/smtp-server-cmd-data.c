/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "array.h"
#include "istream.h"
#include "istream-chain.h"

#include "smtp-command-parser.h"
#include "smtp-server-private.h"

/* DATA/BDAT/B... commands */

struct cmd_data_context {
	struct istream *chunk_input;
	uoff_t chunk_size;

	bool chunking:1;
	bool client_input:1;
	bool chunk_first:1;
	bool chunk_last:1;
};

static void
smtp_server_cmd_data_size_limit_exceeded(struct smtp_server_cmd_ctx *cmd)
{
	struct smtp_server_command *command = cmd->cmd;

	smtp_server_command_fail(command, 552, "5.2.3",
				 "Message size exceeds administrative limit");
}

bool smtp_server_cmd_data_check_size(struct smtp_server_cmd_ctx *cmd)
{
	struct smtp_server_connection *conn = cmd->conn;
	const struct smtp_server_settings *set = &conn->set;

	i_assert(conn->state.state == SMTP_SERVER_STATE_DATA);

	if (conn->state.data_input == NULL)
		return TRUE;
	if (set->max_message_size == 0)
		return TRUE;
	if (conn->state.data_input->v_offset <= set->max_message_size)
		return TRUE;

	smtp_server_cmd_data_size_limit_exceeded(cmd);
	return FALSE;
}

bool smtp_server_connection_data_check_state(struct smtp_server_cmd_ctx *cmd)
{
	struct smtp_server_connection *conn = cmd->conn;
	struct smtp_server_command *command = cmd->cmd;
	struct cmd_data_context *data_cmd = command->data;

	if (conn->state.data_chunks > 0 && conn->state.data_failed) {
		// FIXME: should it even reply anything? RFC is unclear.
		smtp_server_command_fail(command, 503, "5.5.0",
			"Previous data chunk failed, issue RSET first");
		return FALSE;
	}

	/* check valid MAIL */
	if (conn->state.trans == NULL
		&& conn->state.pending_mail_cmds == 0) {
		smtp_server_command_fail(command,
			503, "5.5.0", "MAIL needed first");
		return FALSE;
	}
	if (conn->state.trans != NULL &&
	    (conn->state.trans->params.body.type ==
		SMTP_PARAM_MAIL_BODY_TYPE_BINARYMIME) &&
	    !data_cmd->chunking) {
		/* RFC 3030, Section 3:
		   BINARYMIME cannot be used with the DATA command. If a DATA
		   command is issued after a MAIL command containing the
		   body-value of "BINARYMIME", a 503 "Bad sequence of commands"
		   response MUST be sent. The resulting state from this error
		   condition is indeterminate and the transaction MUST be reset
		   with the RSET command. */
		smtp_server_command_fail(command,
			503, "5.5.0", "DATA cannot be used with BINARYMIME");
		return FALSE;
	}

	/* Can only decide whether we have valid recipients once there are no
	   pending RCPT commands */
	if (conn->state.pending_rcpt_cmds > 0)
		return TRUE;

	/* special handling for LMTP */
	if (conn->set.protocol == SMTP_PROTOCOL_LMTP) {
		/* check valid RCPT (at least one) */
		if (conn->state.trans == NULL ||
		    !smtp_server_transaction_has_rcpt(conn->state.trans)) {
			if (data_cmd->chunk_size > 0 && data_cmd->chunk_last) {
				/* RFC 2033, Section 4.3:
				   If there were no previously successful RCPT
				   commands in the mail transaction, then the
				   BDAT LAST command returns zero replies.
				 */
				smtp_server_command_abort(&command);
			} else {
				/* RFC 2033, Section 4.2:
				   The additional restriction is that when there
				   have been no successful RCPT commands in the
				   mail transaction, the DATA command MUST fail
				   with a 503 reply code.
				*/
				smtp_server_command_fail(command,
					503, "5.5.0", "No valid recipients");
			}
			return FALSE;
		}

	} else {
		/* check valid RCPT (at least one) */
		if (conn->state.trans == NULL ||
			!smtp_server_transaction_has_rcpt(conn->state.trans)) {
			smtp_server_command_fail(command,
				554, "5.5.0", "No valid recipients");
			return FALSE;
		}
	}
	return TRUE;
}

static void cmd_data_destroy(struct smtp_server_cmd_ctx *cmd)
{
	struct smtp_server_connection *conn = cmd->conn;
	struct smtp_server_command *command = cmd->cmd;
	struct cmd_data_context *data_cmd = command->data;

	i_assert(data_cmd != NULL);

	if (data_cmd->chunk_last ||
		!smtp_server_command_replied_success(command)) {
		/* clean up */
		i_stream_destroy(&conn->state.data_input);
		conn->state.data_chain = NULL;
	}

	i_stream_unref(&data_cmd->chunk_input);
}

static void cmd_data_replied(struct smtp_server_cmd_ctx *cmd)
{
	struct smtp_server_command *command = cmd->cmd;

	smtp_server_command_input_lock(cmd);
	if (!smtp_server_command_replied_success(command))
		smtp_server_command_input_unlock(cmd);
}

static void cmd_data_completed(struct smtp_server_cmd_ctx *cmd)
{
	struct smtp_server_connection *conn = cmd->conn;
	struct smtp_server_command *command = cmd->cmd;
	struct cmd_data_context *data_cmd = command->data;

	i_assert(data_cmd != NULL);
	i_stream_unref(&data_cmd->chunk_input);

	/* reset state */
	smtp_server_connection_reset_state(conn);
}

static void cmd_data_chunk_replied(struct smtp_server_cmd_ctx *cmd)
{
	struct smtp_server_connection *conn = cmd->conn;
	struct smtp_server_command *command = cmd->cmd;
	struct cmd_data_context *data_cmd = command->data;

	i_assert(data_cmd != NULL);

	i_assert(smtp_server_command_is_replied(command));
	if (!smtp_server_command_replied_success(command))
		conn->state.data_failed = TRUE;
}

static void
cmd_data_chunk_finish(struct smtp_server_cmd_ctx *cmd)
{
	struct smtp_server_command *command = cmd->cmd;
	struct cmd_data_context *data_cmd = command->data;

	smtp_server_command_input_lock(cmd);
	i_stream_unref(&data_cmd->chunk_input);

	/* re-check transaction state (for BDAT/B... command) */
	if (!smtp_server_connection_data_check_state(cmd))
		return;

	smtp_server_reply(cmd, 250, "2.0.0",
		"Added %"PRIuUOFF_T" octets", data_cmd->chunk_size);
}

static void cmd_data_input_error(struct smtp_server_cmd_ctx *cmd)
{
	struct smtp_server_connection *conn = cmd->conn;
	struct smtp_server_command *command = cmd->cmd;
	struct cmd_data_context *data_cmd = command->data;
	struct istream *data_input = conn->state.data_input;
	unsigned int stream_errno = data_input->stream_errno;

	conn->state.data_failed = TRUE;

	if (!data_cmd->client_input) {
		if (!smtp_server_command_is_replied(command)) {
			smtp_server_command_fail(command,
				400, "4.0.0", "Failed to add data");
		}
		return;
	}

	if (stream_errno != EPIPE && stream_errno != ECONNRESET) {
		smtp_server_connection_error(conn,
			"Connection lost during data transfer: "
			"read(%s) failed: %s",
			i_stream_get_name(data_input),
			i_stream_get_error(data_input));
		smtp_server_connection_close(&conn, "Read failure");
	} else {
		smtp_server_connection_debug(conn,
			"Connection lost during data transfer: "
			"Remote disconnected");
		smtp_server_connection_close(&conn,
			"Remote closed connection unexpectedly");
	}
}

static int cmd_data_do_handle_input(struct smtp_server_cmd_ctx *cmd)
{
	struct smtp_server_connection *conn = cmd->conn;
	const struct smtp_server_callbacks *callbacks = conn->callbacks;
	struct smtp_server_command *command = cmd->cmd;
	struct cmd_data_context *data_cmd = command->data;
	int ret;

	i_assert(data_cmd != NULL);

	i_assert(callbacks != NULL &&
		 callbacks->conn_cmd_data_continue != NULL);
	ret = callbacks->conn_cmd_data_continue(conn->context,
		cmd, conn->state.trans);
	if (ret >= 0) {
		if (!smtp_server_cmd_data_check_size(cmd)) {
			return -1;
		} else if (!i_stream_have_bytes_left(conn->state.data_input)) {
			smtp_server_command_debug(cmd,
				"End of data");
			smtp_server_command_input_lock(cmd);
			smtp_server_connection_timeout_stop(conn);
		} else if (!data_cmd->chunk_last &&
			!i_stream_have_bytes_left(data_cmd->chunk_input)) {
			smtp_server_command_debug(cmd,
				"End of chunk");
			cmd_data_chunk_finish(cmd);
		} else if (i_stream_get_data_size(
			conn->state.data_input) > 0) {
			smtp_server_command_debug(cmd,
				"Not all client data read");			
			smtp_server_connection_timeout_stop(cmd->conn);
		} else {
			smtp_server_connection_timeout_start(cmd->conn);
		}
	} else {
		if (conn->state.data_input->stream_errno != 0) {
			cmd_data_input_error(cmd);
			return -1;
		}
		/* command is waiting for external event or it failed */
		i_assert(smtp_server_command_is_replied(command));
	}
	
	return 1;
}

static int cmd_data_handle_input(struct smtp_server_cmd_ctx *cmd)
{
	struct smtp_server_command *command = cmd->cmd;
	int ret;

	if (!smtp_server_cmd_data_check_size(cmd))
		return -1;

	smtp_server_command_ref(command);

	/* continue reading from client */
	ret = cmd_data_do_handle_input(cmd);
	
	smtp_server_command_unref(&command);

	return ret;
}

static void cmd_data_input(struct smtp_server_cmd_ctx *cmd)
{
	smtp_server_connection_timeout_reset(cmd->conn);
	(void)cmd_data_handle_input(cmd);
}

static void cmd_data_next(struct smtp_server_cmd_ctx *cmd)
{
	struct smtp_server_connection *conn = cmd->conn;
	const struct smtp_server_callbacks *callbacks = conn->callbacks;
	struct smtp_server_command *command = cmd->cmd;
	struct cmd_data_context *data_cmd = command->data;
	int ret;

	/* this command is next to send a reply */

	i_assert(data_cmd != NULL);
	i_assert(conn->state.pending_mail_cmds == 0 &&
		conn->state.pending_rcpt_cmds == 0);

	smtp_server_command_debug(cmd,
		"Command is next to be replied");

	/* check whether we have had successful mail and rcpt commands */
	if (!smtp_server_connection_data_check_state(cmd))
		return;

	/* LMTP 'DATA' and 'BDAT LAST' commands need to send one reply
	   per recipient
	 */
	if (data_cmd->chunk_last && conn->set.protocol == SMTP_PROTOCOL_LMTP) {
		smtp_server_command_set_reply_count(command,
			array_count(&conn->state.trans->rcpt_to));
	}

	smtp_server_connection_set_state(conn, SMTP_SERVER_STATE_DATA);

	/* chain data streams in the correct order */
	if (conn->state.data_chain != NULL) {
		i_assert(data_cmd->chunk_input != NULL);
		i_stream_chain_append(conn->state.data_chain,
				      data_cmd->chunk_input);
		if (data_cmd->chunk_last) {
			smtp_server_command_debug(cmd,
				"Seen the last chunk");
			i_stream_chain_append_eof(conn->state.data_chain);
		}
	}

	if (data_cmd->chunk_first) {
		struct smtp_server_command *cmd_temp = command;

		smtp_server_command_debug(cmd,
			"First chunk");

		smtp_server_command_ref(cmd_temp);
		i_assert(callbacks != NULL &&
			 callbacks->conn_cmd_data_begin != NULL);
		if ((ret=callbacks->conn_cmd_data_begin(conn->context,
			cmd, conn->state.trans, conn->state.data_input)) < 0) {
			i_assert(smtp_server_command_is_replied(cmd_temp));
			/* command failed */
			smtp_server_command_unref(&cmd_temp);
			return;
		}
		if (!smtp_server_command_unref(&cmd_temp))
			return;
	}

	if (smtp_server_command_is_replied(command)) {
		smtp_server_command_input_unlock(cmd);
	} else {
		if (data_cmd->client_input) {
			/* using input from client connection;
			   capture I/O event */
			smtp_server_connection_timeout_start(conn);
			smtp_server_command_input_capture(cmd, cmd_data_input);
		}

		(void)cmd_data_handle_input(cmd);
	}
}

static void cmd_data_start_input(struct smtp_server_cmd_ctx *cmd,
				 struct istream *input)
{
	struct smtp_server_connection *conn = cmd->conn;
	struct smtp_server_command *command = cmd->cmd;
	struct cmd_data_context *data_cmd = command->data;

	i_assert(data_cmd != NULL);

	if (input != NULL) {
		conn->state.data_input = input;
		i_stream_ref(input);
	}

	if (data_cmd->client_input)
		smtp_server_command_input_lock(cmd);

	if (data_cmd->chunk_last)
		command->hook_completed = cmd_data_completed;

	if (conn->state.pending_mail_cmds == 0 &&
		conn->state.pending_rcpt_cmds == 0) {
		cmd_data_next(cmd);
	} else {
		command->hook_next = cmd_data_next;
	}
}

/* DATA command */

static void cmd_data_start(struct smtp_server_cmd_ctx *cmd)
{
	struct smtp_server_connection *conn = cmd->conn;
	struct istream *dot_input;

	/* called when all previous commands were finished */
	i_assert(conn->state.pending_mail_cmds == 0 &&
		conn->state.pending_rcpt_cmds == 0);

	/* check whether we have had successful mail and rcpt commands */
	if (!smtp_server_connection_data_check_state(cmd))
		return;

	/* don't allow classic DATA when CHUNKING sequence was started before */
	if (conn->state.data_chunks > 0) {
		smtp_server_command_fail(cmd->cmd,
			503, "5.5.0", "Bad sequence of commands");
		return;
	}

	smtp_server_connection_set_state(conn, SMTP_SERVER_STATE_DATA);

	/* confirm initial success to client */
	smtp_server_connection_reply_immediate(conn, 354, "OK");

	/* start reading message data from client */
	dot_input = smtp_command_parse_data_with_dot(conn->smtp_parser);
	cmd_data_start_input(cmd, dot_input);
	i_stream_unref(&dot_input);
}

void smtp_server_cmd_data(struct smtp_server_cmd_ctx *cmd,
			  const char *params)
{
	struct smtp_server_command *command = cmd->cmd;
	struct cmd_data_context *data_cmd;

	/* data = "DATA" CRLF */
	if (*params != '\0') {
		smtp_server_reply(cmd,
			501, "5.5.4", "Invalid parameters");
		return;
	}

	smtp_server_command_input_lock(cmd);

	data_cmd = p_new(cmd->pool, struct cmd_data_context, 1);
	data_cmd->chunk_first = TRUE;
	data_cmd->chunk_last = TRUE;
	data_cmd->client_input = TRUE;
	command->data = (void*)data_cmd;

	command->hook_next = cmd_data_start;
	command->hook_replied = cmd_data_replied;
	command->hook_destroy = cmd_data_destroy;
}

/* BDAT/B... commands */

void smtp_server_connection_data_chunk_init(struct smtp_server_cmd_ctx *cmd)
{
	struct smtp_server_connection *conn = cmd->conn;
	struct smtp_server_command *command = cmd->cmd;
	struct cmd_data_context *data_cmd;

	data_cmd = p_new(cmd->pool, struct cmd_data_context, 1);
	command->data = (void *)data_cmd;
	data_cmd->chunking = TRUE;
	data_cmd->chunk_first = (conn->state.data_chunks++ == 0);

	command->hook_replied = cmd_data_chunk_replied;
	command->hook_destroy = cmd_data_destroy;

	if (!conn->state.data_failed && conn->state.data_chain == NULL) {
		i_assert(data_cmd->chunk_first);
		i_assert(conn->state.data_chain_input == NULL);
		conn->state.data_chain_input =
			i_stream_create_chain(&conn->state.data_chain);
	}
}

int smtp_server_connection_data_chunk_add(struct smtp_server_cmd_ctx *cmd,
	struct istream *chunk, uoff_t chunk_size, bool chunk_last,
	bool client_input)
{
	struct smtp_server_connection *conn = cmd->conn;
	const struct smtp_server_settings *set = &conn->set;
	struct smtp_server_command *command = cmd->cmd;
	struct cmd_data_context *data_cmd =
		(struct cmd_data_context *)command->data;
	struct istream *input;
	uoff_t new_size;

	i_assert(data_cmd != NULL);

	if (!smtp_server_connection_data_check_state(cmd))
		return -1;

	/* check message size increase early */
	new_size = conn->state.data_size + chunk_size;
	if (new_size < conn->state.data_size ||
	    (set->max_message_size > 0 && new_size > set->max_message_size)) {
		smtp_server_cmd_data_size_limit_exceeded(cmd);
		return -1;
	}
	conn->state.data_size = new_size;

	command->hook_replied = (chunk_last ?
		cmd_data_replied : cmd_data_chunk_replied);

	data_cmd->chunk_input = chunk;
	data_cmd->chunk_size = chunk_size;
	data_cmd->chunk_last = chunk_last;
	data_cmd->client_input = client_input;
	i_stream_ref(chunk);

	input = (data_cmd->chunk_first ? conn->state.data_chain_input : NULL);
	cmd_data_start_input(cmd, input);
	i_stream_unref(&input);
	return 0;
}

/* BDAT command */

void smtp_server_cmd_bdat(struct smtp_server_cmd_ctx *cmd,
			  const char *params)
{
	struct smtp_server_connection *conn = cmd->conn;
	struct istream *input = NULL;
	uoff_t size = 0;
	const char *const *argv;
	bool chunk_last = FALSE;
	int ret = 1;

	if ((conn->set.capabilities & SMTP_CAPABILITY_CHUNKING) == 0) {
		smtp_server_reply(cmd,
			502, "5.5.1", "Unsupported command");
		return;
	}

	smtp_server_connection_data_chunk_init(cmd);

	/* bdat-cmd   = "BDAT" SP chunk-size [ SP end-marker ] CR LF
	   chunk-size = 1*DIGIT
	   end-marker = "LAST"
	 */
	argv = t_strsplit(params, " ");
	if (argv[0] == NULL || str_to_uoff(argv[0], &size) < 0) {
		smtp_server_reply(cmd,
			501, "5.5.4", "Invalid chunk size parameter");
		size = 0;
		ret = -1;
	} else if (argv[1] != NULL) {
		if (argv[2] != NULL) {
			smtp_server_reply(cmd,
				501, "5.5.4", "Invalid parameters");
			ret = -1;
		} else if (strcasecmp(argv[1], "LAST") != 0) {
			smtp_server_reply(cmd,
				501, "5.5.4", "Invalid end marker parameter");
			ret = -1;
		} else {
			chunk_last = TRUE;
		}
	}

	if (ret > 0 || size > 0) {
		/* read/skip data even in case of error, as long as size is
		   known */
		input = smtp_command_parse_data_with_size(conn->smtp_parser,
							  size);
	}

	if (ret < 0) {
		i_stream_unref(&input);
		return;
	}

	(void)smtp_server_connection_data_chunk_add(cmd,
		input, size, chunk_last, TRUE);
	i_stream_unref(&input);
}
