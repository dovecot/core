/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "commands.h"

int cmd_rename(Client *client)
{
	const char *oldname, *newname;

	/* <old name> <new name> */
	if (!client_read_string_args(client, 2, &oldname, &newname))
		return FALSE;

	if (!client_verify_mailbox_name(client, newname, FALSE))
		return TRUE;

	if (client->storage->rename_mailbox(client->storage,
					    oldname, newname))
		client_send_tagline(client, "OK Rename completed.");
	else
		client_send_storage_error(client);

	return TRUE;
}
