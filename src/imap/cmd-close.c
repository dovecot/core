/* Copyright (c) 2002-2008 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "commands.h"
#include "imap-expunge.h"

bool cmd_close(struct client_command_context *cmd)
{
	struct client *client = cmd->client;
	struct mailbox *mailbox = client->mailbox;
	struct mail_storage *storage;

	if (!client_verify_open_mailbox(cmd))
		return TRUE;

	storage = mailbox_get_storage(mailbox);
	client->mailbox = NULL;

	if (!imap_expunge(mailbox, NULL))
		client_send_untagged_storage_error(client, storage);

	if (mailbox_close(&mailbox) < 0)
                client_send_untagged_storage_error(client, storage);
	client_update_mailbox_flags(client, NULL);

	client_send_tagline(cmd, "OK Close completed.");
	return TRUE;
}
