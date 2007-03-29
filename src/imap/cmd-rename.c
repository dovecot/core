/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "commands.h"

bool cmd_rename(struct client_command_context *cmd)
{
	struct mail_storage *old_storage, *new_storage;
	struct mailbox_list *list;
	const char *oldname, *newname;

	/* <old name> <new name> */
	if (!client_read_string_args(cmd, 2, &oldname, &newname))
		return FALSE;

	if (!client_verify_mailbox_name(cmd, newname, FALSE, TRUE))
		return TRUE;

	old_storage = client_find_storage(cmd, &oldname);
	if (old_storage == NULL)
		return TRUE;

	new_storage = client_find_storage(cmd, &newname);
	if (new_storage == NULL)
		return TRUE;

	if (old_storage != new_storage) {
		client_send_tagline(cmd,
			"NO Can't rename mailbox to another storage type.");
		return TRUE;
	}

	list = mail_storage_get_list(old_storage);
	if (mailbox_list_rename_mailbox(list, oldname, newname) < 0) {
		mail_storage_set_list_error(old_storage);
		client_send_storage_error(cmd, old_storage);
	} else {
		client_send_tagline(cmd, "OK Rename completed.");
	}
	return TRUE;
}
