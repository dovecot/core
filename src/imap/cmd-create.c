/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "commands.h"

int cmd_create(Client *client)
{
	const char *mailbox;
	int ignore;

	/* <mailbox> */
	if (!client_read_string_args(client, 1, &mailbox))
		return FALSE;

	ignore = mailbox[strlen(mailbox)-1] == client->storage->hierarchy_sep;
	if (ignore) {
		/* name ends with hierarchy separator - client is just
		   informing us that it wants to create a mailbox under
		   this name. we don't need that information, but verify
		   that the mailbox name is valid */
		mailbox = t_strndup(mailbox, strlen(mailbox)-1);
	}

	if (!client_verify_mailbox_name(client, mailbox, FALSE, !ignore))
		return TRUE;

	if (!ignore &&
	    !client->storage->create_mailbox(client->storage, mailbox)) {
		client_send_storage_error(client);
		return TRUE;
	}

	client_send_tagline(client, "OK Create completed.");
	return TRUE;
}
