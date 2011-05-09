/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "imap-resp-code.h"
#include "mail-namespace.h"
#include "imap-commands.h"

bool cmd_rename(struct client_command_context *cmd)
{
	enum mailbox_name_status status;
	struct mail_namespace *old_ns, *new_ns;
	struct mailbox *old_box, *new_box;
	const char *oldname, *newname, *storage_oldname, *storage_newname;
	unsigned int oldlen;

	/* <old name> <new name> */
	if (!client_read_string_args(cmd, 2, &oldname, &newname))
		return FALSE;

	old_ns = client_find_namespace(cmd, oldname, &storage_oldname, &status);
	if (old_ns == NULL)
		return TRUE;
	switch (status) {
	case MAILBOX_NAME_EXISTS_MAILBOX:
	case MAILBOX_NAME_EXISTS_DIR:
		break;
	case MAILBOX_NAME_VALID:
	case MAILBOX_NAME_INVALID:
	case MAILBOX_NAME_NOINFERIORS:
		client_fail_mailbox_name_status(cmd, oldname,
						IMAP_RESP_CODE_NONEXISTENT,
						status);
		return TRUE;
	}

	new_ns = client_find_namespace(cmd, newname, &storage_newname, &status);
	if (new_ns == NULL)
		return TRUE;
	switch (status) {
	case MAILBOX_NAME_VALID:
		break;
	case MAILBOX_NAME_EXISTS_MAILBOX:
	case MAILBOX_NAME_EXISTS_DIR:
	case MAILBOX_NAME_INVALID:
	case MAILBOX_NAME_NOINFERIORS:
		client_fail_mailbox_name_status(cmd, newname, NULL, status);
		return TRUE;
	}

	if (old_ns == new_ns) {
		/* disallow box -> box/child, because it may break clients and
		   there's really no point in doing it anyway. */
		old_ns = mailbox_list_get_namespace(old_ns->list);
		oldlen = strlen(storage_oldname);
		if (strncmp(storage_oldname, storage_newname, oldlen) == 0 &&
		    storage_newname[oldlen] == old_ns->real_sep) {
			client_send_tagline(cmd,
				"NO Can't rename mailbox under its own child.");
			return TRUE;
		}
	}

	old_box = mailbox_alloc(old_ns->list, storage_oldname, 0);
	new_box = mailbox_alloc(new_ns->list, storage_newname, 0);
	if (mailbox_rename(old_box, new_box, TRUE) < 0)
		client_send_storage_error(cmd, mailbox_get_storage(old_box));
	else
		client_send_tagline(cmd, "OK Rename completed.");
	mailbox_free(&old_box);
	mailbox_free(&new_box);
	return TRUE;
}
