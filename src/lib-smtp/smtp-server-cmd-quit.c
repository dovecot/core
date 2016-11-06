/* Copyright (c) 2013-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"

#include "smtp-server-private.h"

/* QUIT command */

void smtp_server_cmd_quit(struct smtp_server_cmd_ctx *cmd,
    			  const char *params)
{
	struct smtp_server_connection *conn = cmd->conn;
	struct smtp_server_command *command = cmd->cmd;
	const struct smtp_server_callbacks *callbacks = conn->callbacks;
	int ret;

	/* "QUIT" CRLF */
	if (*params != '\0') {
		smtp_server_reply(cmd,
			501, "5.5.4", "Invalid parameters");
		return;
	}

	smtp_server_connection_input_halt(conn);

	smtp_server_command_ref(command);
	if (callbacks != NULL && callbacks->conn_cmd_quit != NULL) {
		/* specific implementation of QUIT command */
		if ((ret=callbacks->conn_cmd_quit(conn->context, cmd)) <= 0) {
			i_assert(ret == 0 ||
				 smtp_server_command_is_replied(command));
			/* command is waiting for external event or it failed */
			smtp_server_command_unref(&command);
			return;
		}
	}
	if (!smtp_server_command_is_replied(command)) {
		/* set generic QUIT success reply if none is provided */
		smtp_server_reply_quit(cmd);
	}
	smtp_server_command_unref(&command);
}
