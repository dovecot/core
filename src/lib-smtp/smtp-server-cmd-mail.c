/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

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

	if (conn->state.trans != NULL) {
		smtp_server_reply(cmd, 503, "5.5.0", "MAIL already given");
		return FALSE;
	}
	return TRUE;
}

static void
cmd_mail_completed(struct smtp_server_cmd_ctx *cmd,
		   struct smtp_server_cmd_mail *data)
{
	struct smtp_server_connection *conn = cmd->conn;
	struct smtp_server_command *command = cmd->cmd;

	i_assert(conn->state.pending_mail_cmds > 0);
	conn->state.pending_mail_cmds--;

	i_assert(smtp_server_command_is_replied(command));
	if (!smtp_server_command_replied_success(command)) {
		/* failure; substitute our own error if predictable */
		if (smtp_server_command_reply_is_forwarded(command))
			(void)cmd_mail_check_state(cmd);
		return;
	}

	/* success */
	conn->state.trans = smtp_server_transaction_create(conn, data);
}

static void
cmd_mail_recheck(struct smtp_server_cmd_ctx *cmd,
		 struct smtp_server_cmd_mail *data ATTR_UNUSED)
{
	struct smtp_server_connection *conn = cmd->conn;

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
	enum smtp_address_parse_flags path_parse_flags;
	const char *const *param_extensions = NULL;
	struct smtp_address *path = NULL;
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
	if (params[5] != ' ' && params[5] != '\t') {
		params += 5;
	} else if ((set->workarounds &
		    SMTP_SERVER_WORKAROUND_WHITESPACE_BEFORE_PATH) != 0) {
		params += 5;
		while (*params == ' ' || *params == '\t')
			params++;
	} else {
		smtp_server_reply(cmd, 501, "5.5.4",
				  "Invalid FROM: "
				  "Unexpected whitespace before path");
		return;
	}
	path_parse_flags =
		SMTP_ADDRESS_PARSE_FLAG_ALLOW_EMPTY |
		SMTP_ADDRESS_PARSE_FLAG_PRESERVE_RAW;
	if (*params != '\0' &&
	    (set->workarounds & SMTP_SERVER_WORKAROUND_MAILBOX_FOR_PATH) != 0)
		path_parse_flags |= SMTP_ADDRESS_PARSE_FLAG_BRACKETS_OPTIONAL;
	if (set->mail_path_allow_broken) {
		path_parse_flags |=
			SMTP_ADDRESS_PARSE_FLAG_ALLOW_BAD_LOCALPART |
			SMTP_ADDRESS_PARSE_FLAG_IGNORE_BROKEN;
	}
	ret = smtp_address_parse_path_full(pool_datastack_create(), params,
					   path_parse_flags, &path, &error,
					   &params);
	if (ret < 0 && !smtp_address_is_broken(path)) {
		smtp_server_reply(cmd, 501, "5.5.4",
				  "Invalid FROM: %s", error);
		return;
	}
	if (*params == ' ')
		params++;
	else if (*params != '\0') {
		smtp_server_reply(
			cmd, 501, "5.5.4",
			"Invalid FROM: Invalid character in path");
		return;
	}
	if (ret < 0) {
		i_assert(set->mail_path_allow_broken);
		e_debug(conn->event, "Invalid FROM: %s "
			"(proceeding with <> as sender)", error);
	}

	mail_data = p_new(cmd->pool, struct smtp_server_cmd_mail, 1);

	if (conn->set.protocol == SMTP_PROTOCOL_LMTP)
		mail_data->flags |= SMTP_SERVER_TRANSACTION_FLAG_REPLY_PER_RCPT;

	/* [SP Mail-parameters] */
	if (array_is_created(&conn->mail_param_extensions))
		param_extensions = array_front(&conn->mail_param_extensions);
	if (smtp_params_mail_parse(cmd->pool, params, caps, param_extensions,
				   NULL, &mail_data->params, &pperror,
				   &error) < 0) {
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

	if ((caps & SMTP_CAPABILITY_SIZE) != 0 && set->max_message_size > 0 &&
	    mail_data->params.size > set->max_message_size) {
		smtp_server_reply(cmd, 552, "5.2.3",
			"Message size exceeds administrative limit");
		return;
	}

	mail_data->path = smtp_address_clone(cmd->pool, path);
	mail_data->timestamp = ioloop_timeval;

	smtp_server_command_add_hook(command, SMTP_SERVER_COMMAND_HOOK_NEXT,
				     cmd_mail_recheck, mail_data);
	smtp_server_command_add_hook(command, SMTP_SERVER_COMMAND_HOOK_COMPLETED,
				     cmd_mail_completed, mail_data);

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
		smtp_server_cmd_mail_reply_success(cmd);
	}
	smtp_server_command_unref(&command);
}

void smtp_server_cmd_mail_reply_success(struct smtp_server_cmd_ctx *cmd)
{
	i_assert(cmd->cmd->reg->func == smtp_server_cmd_mail);

	smtp_server_reply(cmd, 250, "2.1.0", "OK");
}
