/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "commands.h"

int cmd_delete(Client *client)
{
	const char *mailbox;

	/* <mailbox> */
	if (!client_read_string_args(client, 1, &mailbox))
		return FALSE;

	if (strcasecmp(mailbox, "INBOX") == 0) {
		/* INBOX can't be deleted */
		client_send_tagline(client, "NO INBOX can't be deleted.");
		return TRUE;
	}

	if (client->storage->delete_mailbox(client->storage, mailbox))
		client_send_tagline(client, "OK Delete completed.");
	else
		client_send_storage_error(client);
	return TRUE;
}
