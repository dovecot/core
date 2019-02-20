/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "array.h"
#include "smtp-parser.h"
#include "smtp-address.h"
#include "smtp-reply.h"
#include "smtp-syntax.h"

#include "smtp-server-private.h"

/* RCPT command */

struct smtp_server_cmd_rcpt {
	struct smtp_server_recipient *rcpt;
};

static void
cmd_rcpt_destroy(struct smtp_server_cmd_ctx *cmd ATTR_UNUSED,
		 struct smtp_server_cmd_rcpt *data)
{
	smtp_server_recipient_destroy(&data->rcpt);
}

static bool
cmd_rcpt_check_state(struct smtp_server_cmd_ctx *cmd)
{
	struct smtp_server_connection *conn = cmd->conn;
	struct smtp_server_transaction *trans = conn->state.trans;

	if (conn->state.pending_mail_cmds == 0 && trans == NULL) {
		smtp_server_reply(cmd,
			503, "5.5.0", "MAIL needed first");
		return FALSE;
	}
	if (conn->set.max_recipients > 0 && trans != NULL &&
		smtp_server_transaction_rcpt_count(trans) >=
			conn->set.max_recipients) {
		smtp_server_reply(cmd,
			451, "4.5.3", "Too many recipients");
		return FALSE;
	}

	return TRUE;
}

static void
cmd_rcpt_completed(struct smtp_server_cmd_ctx *cmd,
		   struct smtp_server_cmd_rcpt *data)
{
	struct smtp_server_connection *conn = cmd->conn;
	struct smtp_server_command *command = cmd->cmd;
	struct smtp_server_recipient *rcpt = data->rcpt;

	i_assert(conn->state.pending_rcpt_cmds > 0);
	conn->state.pending_rcpt_cmds--;

	i_assert(smtp_server_command_is_replied(command));
	if (!smtp_server_command_replied_success(command)) {
		/* failure; substitute our own error if predictable */
		if (smtp_server_command_reply_is_forwarded(command))
			(void)cmd_rcpt_check_state(cmd);
		return;
	}

	/* success */
	data->rcpt = NULL; /* clear to prevent destruction */
	(void)smtp_server_recipient_approved(&rcpt);
}

static void
cmd_rcpt_recheck(struct smtp_server_cmd_ctx *cmd,
		 struct smtp_server_cmd_rcpt *data ATTR_UNUSED)
{
	struct smtp_server_connection *conn = cmd->conn;

	i_assert(conn->state.pending_mail_cmds == 0);

	/* all preceeding commands have finished and now the transaction state
	   is clear. This provides the opportunity to re-check the transaction
	   state and abort the pending proxied mail command if it is bound to
	   fail */
	if (!cmd_rcpt_check_state(cmd))
		return;

	/* Advance state */
	smtp_server_connection_set_state(conn, SMTP_SERVER_STATE_RCPT_TO);
}

void smtp_server_cmd_rcpt(struct smtp_server_cmd_ctx *cmd,
			  const char *params)
{
	struct smtp_server_connection *conn = cmd->conn;
	const struct smtp_server_settings *set = &conn->set;
	enum smtp_capability caps = set->capabilities;
	const struct smtp_server_callbacks *callbacks = conn->callbacks;
	struct smtp_server_command *command = cmd->cmd;
	struct smtp_server_cmd_rcpt *rcpt_data;
	struct smtp_server_recipient *rcpt;
	enum smtp_address_parse_flags path_parse_flags;
	const char *const *param_extensions = NULL;
	struct smtp_address *path;
	enum smtp_param_parse_error pperror;
	const char *error;
	int ret;

	/* rcpt         = "RCPT TO:" ( "<Postmaster@" Domain ">" /
	      "<Postmaster>" / Forward-path ) [SP Rcpt-parameters] CRLF
	   Forward-path = Path
	 */

	/* check transaction state as far as possible */
	if (!cmd_rcpt_check_state(cmd))
		return;

	/* ( "<Postmaster@" Domain ">" / "<Postmaster>" / Forward-path ) */
	if (params == NULL || strncasecmp(params, "TO:", 3) != 0) {
		smtp_server_reply(cmd,
			501, "5.5.4", "Invalid parameters");
		return;
	}
	if (params[3] != ' ' && params[3] != '\t') {
		params += 3;
	} else if ((set->workarounds &
		    SMTP_SERVER_WORKAROUND_WHITESPACE_BEFORE_PATH) != 0) {
		params += 3;
		while (*params == ' ' || *params == '\t')
			params++;
	} else {
		smtp_server_reply(cmd, 501, "5.5.4",
				  "Invalid TO: "
				  "Unexpected whitespace before path");
		return;
	}
	path_parse_flags = SMTP_ADDRESS_PARSE_FLAG_ALLOW_LOCALPART;
	if ((set->workarounds & SMTP_SERVER_WORKAROUND_MAILBOX_FOR_PATH) != 0)
		path_parse_flags |= SMTP_ADDRESS_PARSE_FLAG_BRACKETS_OPTIONAL;
	if (smtp_address_parse_path_full(pool_datastack_create(), params,
					 path_parse_flags, &path, &error,
					 &params) < 0) {
		smtp_server_reply(cmd,
			501, "5.5.4", "Invalid TO: %s", error);
		return;
	}
	if (*params == ' ')
		params++;
	else if (*params != '\0') {
		smtp_server_reply(cmd, 501, "5.5.4",
			"Invalid TO: Invalid character in path");
		return;
	}
	if (path->domain == NULL && !conn->set.rcpt_domain_optional &&
		strcasecmp(path->localpart, "postmaster") != 0) {
		smtp_server_reply(cmd,
			501, "5.5.4", "Invalid TO: Missing domain");
		return;
	}

	rcpt = smtp_server_recipient_create(cmd, path);

	rcpt_data = p_new(cmd->pool, struct smtp_server_cmd_rcpt, 1);
	rcpt_data->rcpt = rcpt;

	/* [SP Rcpt-parameters] */
	if (array_is_created(&conn->rcpt_param_extensions))
		param_extensions = array_front(&conn->rcpt_param_extensions);
	if (smtp_params_rcpt_parse(rcpt->pool, params, caps, param_extensions,
				   &rcpt->params, &pperror, &error) < 0) {
		switch (pperror) {
		case SMTP_PARAM_PARSE_ERROR_BAD_SYNTAX:
			smtp_server_reply(cmd,
				501, "5.5.4", "%s", error);
			break;
		case SMTP_PARAM_PARSE_ERROR_NOT_SUPPORTED:
			smtp_server_reply(cmd,
				555, "5.5.4", "%s", error);
			break;
		default:
			i_unreached();
		}
		return;
	}

	smtp_server_command_add_hook(command, SMTP_SERVER_COMMAND_HOOK_NEXT,
				     cmd_rcpt_recheck, rcpt_data);
	smtp_server_command_add_hook(command, SMTP_SERVER_COMMAND_HOOK_COMPLETED,
				     cmd_rcpt_completed, rcpt_data);
	smtp_server_command_add_hook(command, SMTP_SERVER_COMMAND_HOOK_DESTROY,
				     cmd_rcpt_destroy, rcpt_data);
	
	conn->state.pending_rcpt_cmds++;

	smtp_server_command_ref(command);
	i_assert(callbacks != NULL && callbacks->conn_cmd_rcpt != NULL);
	if ((ret=callbacks->conn_cmd_rcpt(conn->context, cmd, rcpt)) <= 0) {
		i_assert(ret == 0 || smtp_server_command_is_replied(command));
		/* command is waiting for external event or it failed */
		smtp_server_command_unref(&command);
		return;
	}
	if (!smtp_server_command_is_replied(command)) {
		/* set generic RCPT success reply if none is provided */
		smtp_server_cmd_rcpt_reply_success(cmd);
	}
	smtp_server_command_unref(&command);
}

void smtp_server_cmd_rcpt_reply_success(struct smtp_server_cmd_ctx *cmd)
{
	i_assert(cmd->cmd->reg->func == smtp_server_cmd_rcpt);

	smtp_server_reply(cmd, 250, "2.1.5", "OK");
}
