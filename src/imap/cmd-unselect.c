/* Copyright (c) 2002-2017 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "imap-commands.h"

bool cmd_unselect(struct client_command_context *cmd)
{
	struct client *client = cmd->client;

	if (!client_verify_open_mailbox(cmd))
		return TRUE;

	i_assert(client->mailbox_change_lock == NULL);

	imap_client_close_mailbox(client);
	client_send_tagline(cmd, "OK Unselect completed.");
	return TRUE;
}
