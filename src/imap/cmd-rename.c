/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "mail-namespace.h"
#include "imap-commands.h"

bool cmd_rename(struct client_command_context *cmd)
{
	struct mail_namespace *old_ns, *new_ns;
	struct mailbox *old_box, *new_box;
	const char *suffix, *oldname, *newname;

	/* <old name> <new name> */
	if (!client_read_string_args(cmd, 2, &oldname, &newname))
		return FALSE;

	old_ns = client_find_namespace(cmd, &oldname);
	if (old_ns == NULL)
		return TRUE;
	new_ns = client_find_namespace(cmd, &newname);
	if (new_ns == NULL)
		return TRUE;

	if (old_ns == new_ns) {
		/* disallow box -> box/child, because it may break clients and
		   there's really no point in doing it anyway. */
		old_ns = mailbox_list_get_namespace(old_ns->list);
		if (str_begins(newname, oldname, &suffix) &&
		    suffix[0] == mail_namespace_get_sep(old_ns)) {
			client_send_tagline(cmd,
				"NO Can't rename mailbox under its own child.");
			return TRUE;
		}
	}

	old_box = mailbox_alloc(old_ns->list, oldname, 0);
	new_box = mailbox_alloc(new_ns->list, newname, 0);
	event_add_str(cmd->global_event, "old_mailbox",
		      mailbox_get_vname(old_box));
	event_add_str(cmd->global_event, "new_mailbox",
		      mailbox_get_vname(new_box));
	if (mailbox_rename(old_box, new_box) < 0)
		client_send_box_error(cmd, old_box);
	else
		client_send_tagline(cmd, "OK Rename completed.");
	mailbox_free(&old_box);
	mailbox_free(&new_box);
	return TRUE;
}
