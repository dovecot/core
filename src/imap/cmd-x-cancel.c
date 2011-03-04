/* Copyright (c) 2006-2011 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "imap-commands.h"

bool cmd_x_cancel(struct client_command_context *cmd)
{
	struct client_command_context *cancel_cmd;
	const char *tag;

	/* <tag> */
	if (!client_read_string_args(cmd, 1, &tag))
		return FALSE;

	cancel_cmd = cmd->client->command_queue;
	for (; cancel_cmd != NULL; cancel_cmd = cancel_cmd->next) {
		if (cancel_cmd->tag != NULL && cancel_cmd != cmd &&
		    strcmp(cancel_cmd->tag, tag) == 0) {
			client_command_cancel(&cancel_cmd);
			client_send_tagline(cmd, "OK Command cancelled.");
			return TRUE;
		}
	}

	client_send_tagline(cmd, "NO Command tag not found.");
	return TRUE;
}

