/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "smtp-syntax.h"

#include "smtp-server-private.h"

/* VRFY command */

void smtp_server_cmd_vrfy(struct smtp_server_cmd_ctx *cmd,
			  const char *params)
{
	struct smtp_server_connection *conn = cmd->conn;
	struct smtp_server_command *command = cmd->cmd;
	const struct smtp_server_callbacks *callbacks = conn->callbacks;
	const char *param, *error;
	int ret;

	/* vrfy = "VRFY" SP String CRLF */
	ret = smtp_string_parse(params, &param, &error);
	if (ret < 0) {
		smtp_server_reply(cmd, 501, "5.5.4",
				  "Invalid string parameter: %s", error);
		return;
	} else if (ret == 0) {
		smtp_server_reply(cmd, 501, "5.5.4", "Invalid parameters");
		return;
	}

	smtp_server_command_ref(command);
	if (callbacks != NULL && callbacks->conn_cmd_vrfy != NULL) {
		/* specific implementation of VRFY command */
		ret = callbacks->conn_cmd_vrfy(conn->context, cmd, param);
		if (ret <= 0) {
			i_assert(ret == 0 ||
				 smtp_server_command_is_replied(command));
			/* command is waiting for external event or it failed */
			smtp_server_command_unref(&command);
			return;
		}
	}

	/* RFC 5321, Section 3.5.3:

	   A server MUST NOT return a 250 code in response to a VRFY or EXPN
	   command unless it has actually verified the address. In particular,
	   a server MUST NOT return 250 if all it has done is to verify that the
	   syntax given is valid. In that case, 502 (Command not implemented)
	   or 500 (Syntax error, command unrecognized) SHOULD be returned. As
	   stated elsewhere, implementation (in the sense of actually validating
	   addresses and returning information) of VRFY and EXPN are strongly
	   recommended. Hence, implementations that return 500 or 502 for VRFY
	   are not in full compliance with this specification.

	   There may be circumstances where an address appears to be valid but
	   cannot reasonably be verified in real time, particularly when a
	   server is acting as a mail exchanger for another server or domain.
	   "Apparent validity", in this case, would normally involve at least
	   syntax checking and might involve verification that any domains
	   specified were ones to which the host expected to be able to relay
	   mail. In these situations, reply code 252 SHOULD be returned.
	 */
	if (!smtp_server_command_is_replied(command))
		smtp_server_cmd_vrfy_reply_default(cmd);
	smtp_server_command_unref(&command);
}

void smtp_server_cmd_vrfy_reply_default(struct smtp_server_cmd_ctx *cmd)
{
	i_assert(cmd->cmd->reg->func == smtp_server_cmd_vrfy);

	smtp_server_reply(cmd, 252, "2.3.3", "Try RCPT instead");
}
