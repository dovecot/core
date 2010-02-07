/* Copyright (c) 2002-2010 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "imap-commands.h"

bool cmd_delete(struct client_command_context *cmd)
{
	struct client *client = cmd->client;
	struct mail_namespace *ns;
	struct mailbox *mailbox;
	const char *name;

	/* <mailbox> */
	if (!client_read_string_args(cmd, 1, &name))
		return FALSE;

	if (strcasecmp(name, "INBOX") == 0) {
		/* INBOX can't be deleted */
		client_send_tagline(cmd, "NO INBOX can't be deleted.");
		return TRUE;
	}

	ns = client_find_namespace(cmd, &name,
				   CLIENT_VERIFY_MAILBOX_SHOULD_EXIST);
	if (ns == NULL)
		return TRUE;

	mailbox = mailbox_alloc(ns->list, name, NULL, 0);
	if (client->mailbox != NULL &&
	    mailbox_backends_equal(mailbox, client->mailbox)) {
		/* deleting selected mailbox. close it first */
		client_search_updates_free(client);
		mailbox_free(&client->mailbox);
	}
	mailbox_free(&mailbox);

	if (mailbox_list_delete_mailbox(ns->list, name) < 0)
		client_send_list_error(cmd, ns->list);
	else {
		client_send_tagline(cmd, "OK Delete completed.");
	}
	return TRUE;
}
