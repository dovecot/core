/* Copyright (c) 2002-2009 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "mail-namespace.h"
#include "imap-commands.h"

bool cmd_rename(struct client_command_context *cmd)
{
	struct mail_storage *old_storage, *new_storage;
	struct mailbox_list *old_list, *new_list;
	struct mail_namespace *old_ns;
	const char *oldname, *newname;
	unsigned int oldlen;

	/* <old name> <new name> */
	if (!client_read_string_args(cmd, 2, &oldname, &newname))
		return FALSE;

	if (!client_verify_mailbox_name(cmd, newname, FALSE, TRUE))
		return TRUE;

	old_storage = client_find_storage(cmd, &oldname);
	if (old_storage == NULL)
		return TRUE;
	old_list = mail_storage_get_list(old_storage);

	new_storage = client_find_storage(cmd, &newname);
	if (new_storage == NULL)
		return TRUE;
	new_list = mail_storage_get_list(new_storage);

	if (old_storage == new_storage) {
		/* disallow box -> box/child, because it may break clients and
		   there's really no point in doing it anyway. */
		old_ns = mailbox_list_get_namespace(old_list);
		oldlen = strlen(oldname);
		if (strncmp(oldname, newname, oldlen) == 0 &&
		    newname[oldlen] == old_ns->real_sep) {
			client_send_tagline(cmd,
				"NO Can't rename mailbox under its own child.");
			return TRUE;
		}
	}

	if (mailbox_list_rename_mailbox(old_list, oldname,
					new_list, newname, TRUE) < 0)
		client_send_list_error(cmd, old_list);
	else
		client_send_tagline(cmd, "OK Rename completed.");
	return TRUE;
}
