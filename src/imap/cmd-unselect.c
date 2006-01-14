/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "commands.h"

bool cmd_unselect(struct client_command_context *cmd)
{
	struct client *client = cmd->client;
	struct mailbox *mailbox = client->mailbox;
	struct mail_storage *storage;

	if (!client_verify_open_mailbox(cmd))
		return TRUE;

	client->mailbox = NULL;

	storage = mailbox_get_storage(mailbox);
	if (mailbox_close(&mailbox) < 0)
		client_send_untagged_storage_error(client, storage);

	client_send_tagline(cmd, "OK Unselect completed.");
	return TRUE;
}
