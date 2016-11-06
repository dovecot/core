/* Copyright (c) 2013-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "smtp-parser.h"
#include "smtp-syntax.h"
#include "smtp-address.h"

#include "smtp-server-private.h"

/* MAIL command */

static bool
cmd_mail_check_state(struct smtp_server_cmd_ctx *cmd)
{
	struct smtp_server_connection *conn = cmd->conn;
	struct smtp_server_command *command = cmd->cmd;

	if (conn->state.trans != NULL) {
		if (command->hook_replied != NULL) {
			conn->state.pending_mail_cmds--;
			command->hook_replied = NULL;
		}
		smtp_server_reply(cmd, 503, "5.5.0", "MAIL already given");
		return FALSE;
	}
	return TRUE;
}

static void cmd_mail_replied(struct smtp_server_cmd_ctx *cmd)
{
	struct smtp_server_connection *conn = cmd->conn;
	struct smtp_server_command *command = cmd->cmd;
	struct smtp_server_cmd_mail *data =
		(struct smtp_server_cmd_mail *)command->data;

	conn->state.pending_mail_cmds--;

	i_assert(smtp_server_command_is_replied(command));
	if (!smtp_server_command_replied_success(command)) {
		/* failure; substitute our own error if predictable */
		(void)cmd_mail_check_state(cmd);
		return;
	}

	/* success */
	conn->state.trans = smtp_server_transaction_create(conn,
		data->path, &data->params, &data->timestamp);
}

static void cmd_mail_recheck(struct smtp_server_cmd_ctx *cmd)
{
	struct smtp_server_connection *conn = cmd->conn;

	i_assert(conn->state.pending_rcpt_cmds == 0);

	/* all preceeding commands have finished and now the transaction state
	   is clear. This provides the opportunity to re-check the transaction
	   state */
	if (!cmd_mail_check_state(cmd))
		return;

	/* Advance state */
	smtp_server_connection_set_state(conn, SMTP_SERVER_STATE_MAIL_FROM);
}

void smtp_server_cmd_mail(struct smtp_server_cmd_ctx *cmd,
			  const char *params)
{
	struct smtp_server_connection *conn = cmd->conn;
	const struct smtp_server_settings *set = &conn->set;
	enum smtp_capability caps = set->capabilities;
	const struct smtp_server_callbacks *callbacks = conn->callbacks;
	struct smtp_server_command *command = cmd->cmd;
	struct smtp_server_cmd_mail *mail_data;
	struct smtp_address *path;
	enum smtp_param_parse_error pperror;
	const char *error;
	int ret;

	/* mail         = "MAIL FROM:" Reverse-path [SP Mail-parameters] CRLF
	   Reverse-path = Path / "<>"
	 */

	/* check transaction state as far as possible */
	if (!cmd_mail_check_state(cmd))
		return;

	/* Reverse-path */
	if (params == NULL || strncasecmp(params, "FROM:", 5) != 0) {
		smtp_server_reply(cmd, 501, "5.5.4", "Invalid parameters");
		return;
	}
	if (smtp_address_parse_path_full(pool_datastack_create(), params + 5,
					 SMTP_ADDRESS_PARSE_FLAG_ALLOW_EMPTY,
					 &path, &error, &params) < 0) {
		smtp_server_reply(cmd, 501, "5.5.4", "Invalid FROM: %s", error);
		return;
	}
	if (*params == ' ')
		params++;
	else if (*params != '\0') {
		smtp_server_reply(cmd, 501, "5.5.4",
			"Invalid FROM: Invalid character in path");
		return;
	}

	if (conn->pending_helo == NULL && conn->helo.domain == NULL) {
		/* no EHLO executed post-login, use pre-login value instead */
		conn->helo_domain = conn->helo_login;
		conn->helo_login = NULL;
		conn->helo.domain = conn->helo_domain;
	}

	mail_data = p_new(cmd->pool, struct smtp_server_cmd_mail, 1);

	/* [SP Mail-parameters] */
	if (smtp_params_mail_parse(cmd->pool, params, caps,
				   set->param_extensions, &mail_data->params,
				   &pperror, &error) < 0) {
		switch (pperror) {
		case SMTP_PARAM_PARSE_ERROR_BAD_SYNTAX:
			smtp_server_reply(cmd, 501, "5.5.4", "%s", error);
			break;
		case SMTP_PARAM_PARSE_ERROR_NOT_SUPPORTED:
			smtp_server_reply(cmd, 555, "5.5.4", "%s", error);
			break;
		default:
			i_unreached();
		}
		return;
	}

	mail_data->path = smtp_address_clone(cmd->pool, path);
	mail_data->timestamp = ioloop_timeval;

	command->data = mail_data;
	command->hook_next = cmd_mail_recheck;
	command->hook_replied = cmd_mail_replied;
	smtp_server_connection_set_state(conn, SMTP_SERVER_STATE_MAIL_FROM);
	conn->state.pending_mail_cmds++;

	smtp_server_command_ref(command);
	if (callbacks != NULL && callbacks->conn_cmd_mail != NULL) {
		/* specific implementation of MAIL command */
		if ((ret=callbacks->conn_cmd_mail(conn->context,
			cmd, mail_data)) <= 0) {
			i_assert(ret == 0 ||
				 smtp_server_command_is_replied(command));
			/* command is waiting for external event or it failed */
			smtp_server_command_unref(&command);
			return;
		}
	}
	if (!smtp_server_command_is_replied(command)) {
		/* set generic MAIL success reply if none is provided */
		smtp_server_reply(cmd, 250, "2.1.0", "OK");
	}
	smtp_server_command_unref(&command);
}
