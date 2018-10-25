/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"

#include "smtp-server-private.h"

/* RSET command */

static void
cmd_rset_completed(struct smtp_server_cmd_ctx *cmd, void *context ATTR_UNUSED)
{
	struct smtp_server_connection *conn = cmd->conn;
	struct smtp_server_command *command = cmd->cmd;

	i_assert(smtp_server_command_is_replied(command));
	if (!smtp_server_command_replied_success(command)) {
		/* failure */
		return;
	}

	/* success */
	smtp_server_connection_reset_state(conn);
}

void smtp_server_cmd_rset(struct smtp_server_cmd_ctx *cmd,
			  const char *params)
{
	struct smtp_server_connection *conn = cmd->conn;
	const struct smtp_server_callbacks *callbacks = conn->callbacks;
	struct smtp_server_command *command = cmd->cmd;
	int ret;

	/* rset = "RSET" CRLF */
	if (*params != '\0') {
		smtp_server_reply(cmd,
			501, "5.5.4", "Invalid parameters");
		return;
	}

	smtp_server_command_input_lock(cmd);
	smtp_server_command_add_hook(command, SMTP_SERVER_COMMAND_HOOK_COMPLETED,
				     cmd_rset_completed, NULL);

	smtp_server_command_ref(command);
	if (callbacks != NULL && callbacks->conn_cmd_rset != NULL) {
		/* specific implementation of RSET command */
		if ((ret=callbacks->conn_cmd_rset(conn->context, cmd)) <= 0) {
			i_assert(ret == 0 ||
				 smtp_server_command_is_replied(command));
			/* command is waiting for external event or it failed */
			smtp_server_command_unref(&command);
			return;
		}
	}

	if (!smtp_server_command_is_replied(command)) {
		/* set generic RSET success reply if none is provided */
		smtp_server_cmd_rset_reply_success(cmd);
	}
	smtp_server_command_unref(&command);;
}

void smtp_server_cmd_rset_reply_success(struct smtp_server_cmd_ctx *cmd)
{
	i_assert(cmd->cmd->reg->func == smtp_server_cmd_rset);

	smtp_server_reply(cmd, 250, "2.0.0", "OK");
}
