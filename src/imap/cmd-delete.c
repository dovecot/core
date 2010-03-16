/* Copyright (c) 2002-2010 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "imap-commands.h"

bool cmd_delete(struct client_command_context *cmd)
{
	struct client *client = cmd->client;
	enum mailbox_name_status status;
	struct mail_namespace *ns;
	struct mailbox *box;
	const char *name, *storage_name;

	/* <mailbox> */
	if (!client_read_string_args(cmd, 1, &name))
		return FALSE;

	if (strcasecmp(name, "INBOX") == 0) {
		/* INBOX can't be deleted */
		client_send_tagline(cmd, "NO INBOX can't be deleted.");
		return TRUE;
	}

	ns = client_find_namespace(cmd, name, &storage_name, &status);
	if (ns == NULL)
		return TRUE;
	switch (status) {
	case MAILBOX_NAME_EXISTS_MAILBOX:
	case MAILBOX_NAME_EXISTS_DIR:
		break;
	case MAILBOX_NAME_VALID:
	case MAILBOX_NAME_INVALID:
	case MAILBOX_NAME_NOINFERIORS:
		client_fail_mailbox_name_status(cmd, name, NULL, status);
		return TRUE;
	}

	box = mailbox_alloc(ns->list, storage_name, 0);
	if (client->mailbox != NULL &&
	    mailbox_backends_equal(box, client->mailbox)) {
		/* deleting selected mailbox. close it first */
		client_search_updates_free(client);
		mailbox_free(&client->mailbox);
	}

	if (mailbox_delete(box) < 0)
		client_send_storage_error(cmd, mailbox_get_storage(box));
	else
		client_send_tagline(cmd, "OK Delete completed.");
	mailbox_free(&box);
	return TRUE;
}
