/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "commands.h"

int cmd_rename(struct client *client)
{
	struct mail_storage *old_storage, *new_storage;
	const char *oldname, *newname;

	/* <old name> <new name> */
	if (!client_read_string_args(client, 2, &oldname, &newname))
		return FALSE;

	if (!client_verify_mailbox_name(client, newname, FALSE, TRUE))
		return TRUE;

	old_storage = client_find_storage(client, oldname);
	if (old_storage == NULL)
		return TRUE;

	new_storage = client_find_storage(client, newname);
	if (new_storage == NULL)
		return TRUE;

	if (old_storage != new_storage) {
		client_send_tagline(client,
			"NO Can't rename mailbox to another storage type.");
		return TRUE;
	}

	if (old_storage->rename_mailbox(old_storage, oldname, newname))
		client_send_tagline(client, "OK Rename completed.");
	else
		client_send_storage_error(client, old_storage);

	return TRUE;
}
