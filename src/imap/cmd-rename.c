/* Copyright (c) 2002-2010 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "mail-namespace.h"
#include "imap-commands.h"

bool cmd_rename(struct client_command_context *cmd)
{
	struct mail_namespace *old_ns, *new_ns;
	const char *oldname, *newname;
	unsigned int oldlen;

	/* <old name> <new name> */
	if (!client_read_string_args(cmd, 2, &oldname, &newname))
		return FALSE;

	old_ns = client_find_namespace(cmd, &oldname,
				       CLIENT_VERIFY_MAILBOX_DIR_SHOULD_EXIST);
	if (old_ns == NULL)
		return TRUE;

	new_ns = client_find_namespace(cmd, &newname,
				       CLIENT_VERIFY_MAILBOX_SHOULD_NOT_EXIST);
	if (new_ns == NULL)
		return TRUE;

	if (old_ns == new_ns) {
		/* disallow box -> box/child, because it may break clients and
		   there's really no point in doing it anyway. */
		old_ns = mailbox_list_get_namespace(old_ns->list);
		oldlen = strlen(oldname);
		if (strncmp(oldname, newname, oldlen) == 0 &&
		    newname[oldlen] == old_ns->real_sep) {
			client_send_tagline(cmd,
				"NO Can't rename mailbox under its own child.");
			return TRUE;
		}
	}

	if (mailbox_list_rename_mailbox(old_ns->list, oldname,
					new_ns->list, newname, TRUE) < 0)
		client_send_list_error(cmd, old_ns->list);
	else
		client_send_tagline(cmd, "OK Rename completed.");
	return TRUE;
}
