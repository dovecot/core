/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "imap-resp-code.h"
#include "mail-namespace.h"
#include "imap-commands.h"

bool cmd_create(struct client_command_context *cmd)
{
	enum mailbox_name_status status;
	struct mail_namespace *ns;
	const char *mailbox, *storage_name;
	struct mailbox *box;
	bool directory;
	size_t len;

	/* <mailbox> */
	if (!client_read_string_args(cmd, 1, &mailbox))
		return FALSE;

	ns = client_find_namespace(cmd, mailbox, &storage_name, NULL);
	if (ns == NULL)
		return TRUE;

	len = strlen(mailbox);
	if (len == 0 || mailbox[len-1] != ns->sep)
		directory = FALSE;
	else if (*storage_name == '\0') {
		client_send_tagline(cmd, "NO ["IMAP_RESP_CODE_ALREADYEXISTS
				    "] Namespace already exists.");
		return TRUE;
	} else {
		/* name ends with hierarchy separator - client is just
		   informing us that it wants to create children under this
		   mailbox. */
                directory = TRUE;
		storage_name = t_strndup(storage_name, strlen(storage_name)-1);
		mailbox = t_strndup(mailbox, len-1);
	}

	ns = client_find_namespace(cmd, mailbox, &storage_name, &status);
	if (ns == NULL)
		return TRUE;
	switch (status) {
	case MAILBOX_NAME_VALID:
		break;
	case MAILBOX_NAME_EXISTS_DIR:
		if (!directory)
			break;
		/* fall through */
	case MAILBOX_NAME_EXISTS_MAILBOX:
	case MAILBOX_NAME_INVALID:
	case MAILBOX_NAME_NOINFERIORS:
		client_fail_mailbox_name_status(cmd, mailbox, NULL, status);
		return TRUE;
	}

	box = mailbox_alloc(ns->list, storage_name, 0);
	if (mailbox_create(box, NULL, directory) < 0)
		client_send_storage_error(cmd, mailbox_get_storage(box));
	else
		client_send_tagline(cmd, "OK Create completed.");
	mailbox_free(&box);
	return TRUE;
}
