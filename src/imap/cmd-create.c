/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "commands.h"

int cmd_create(Client *client)
{
	const char *mailbox;

	/* <mailbox> */
	if (!client_read_string_args(client, 1, &mailbox))
		return FALSE;

	if (!client_verify_mailbox_name(client, mailbox, FALSE))
		return TRUE;

	if (mailbox[strlen(mailbox)-1] == client->storage->hierarchy_sep) {
		/* name ends with hierarchy separator - client is just
		   informing us that it wants to create a mailbox under
		   this name. we don't need that information. */
	} else if (!client->storage->create_mailbox(client->storage, mailbox)) {
		client_send_storage_error(client);
		return TRUE;
	}

	client_send_tagline(client, "OK Create completed.");
	return TRUE;
}
