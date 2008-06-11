/* Copyright (c) 2002-2008 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "commands.h"

bool cmd_unselect(struct client_command_context *cmd)
{
	struct client *client = cmd->client;
	struct mailbox *mailbox = client->mailbox;
	struct mail_storage *storage;

	if (!client_verify_open_mailbox(cmd))
		return TRUE;

	client_search_updates_free(client);

	i_assert(client->mailbox_change_lock == NULL);
	client->mailbox = NULL;

	storage = mailbox_get_storage(mailbox);
	if (mailbox_close(&mailbox) < 0)
		client_send_untagged_storage_error(client, storage);
	client_update_mailbox_flags(client, NULL);

	client_send_tagline(cmd, "OK Unselect completed.");
	return TRUE;
}
