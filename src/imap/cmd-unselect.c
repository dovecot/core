/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "imap-commands.h"

bool cmd_unselect(struct client_command_context *cmd)
{
	struct client *client = cmd->client;
	struct mailbox *mailbox = client->mailbox;

	if (!client_verify_open_mailbox(cmd))
		return TRUE;

	client_search_updates_free(client);

	i_assert(client->mailbox_change_lock == NULL);
	client->mailbox = NULL;

	mailbox_free(&mailbox);
	client_update_mailbox_flags(client, NULL);

	client_send_tagline(cmd, "OK Unselect completed.");
	return TRUE;
}
