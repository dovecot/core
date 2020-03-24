/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "smtp-syntax.h"

#include "smtp-server-private.h"

/* NOOP command */

void smtp_server_cmd_noop(struct smtp_server_cmd_ctx *cmd,
			  const char *params)
{
	struct smtp_server_connection *conn = cmd->conn;
	struct smtp_server_command *command = cmd->cmd;
	const struct smtp_server_callbacks *callbacks = conn->callbacks;
	int ret;

	/* "NOOP" [ SP String ] CRLF */
	if (*params != '\0' && smtp_string_parse(params, NULL, NULL) < 0) {
		smtp_server_reply(cmd, 501, "5.5.4", "Invalid parameters");
		return;
	}

	smtp_server_command_input_lock(cmd);

	smtp_server_command_ref(command);
	if (callbacks != NULL && callbacks->conn_cmd_noop != NULL) {
		/* specific implementation of NOOP command */
		ret = callbacks->conn_cmd_noop(conn->context, cmd);
		if (ret <= 0) {
			i_assert(ret == 0 ||
				 smtp_server_command_is_replied(command));
			/* command is waiting for external event or it failed */
			smtp_server_command_unref(&command);
			return;
		}
	}
	if (!smtp_server_command_is_replied(command))
		smtp_server_cmd_noop_reply_success(cmd);
	smtp_server_command_unref(&command);
}

void smtp_server_cmd_noop_reply_success(struct smtp_server_cmd_ctx *cmd)
{
       i_assert(cmd->cmd->reg->func == smtp_server_cmd_noop);

       smtp_server_reply(cmd, 250, "2.0.0", "OK");
}
