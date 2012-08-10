/* Copyright (c) 2002-2012 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "imap-commands.h"

bool cmd_delete(struct client_command_context *cmd)
{
	struct client *client = cmd->client;
	struct mail_namespace *ns;
	struct mailbox *box;
	const char *name, *errstr;
	enum mail_error error;
	bool disconnect = FALSE;

	/* <mailbox> */
	if (!client_read_string_args(cmd, 1, &name))
		return FALSE;

	if (strcasecmp(name, "INBOX") == 0) {
		/* INBOX can't be deleted */
		client_send_tagline(cmd, "NO INBOX can't be deleted.");
		return TRUE;
	}

	ns = client_find_namespace(cmd, &name);
	if (ns == NULL)
		return TRUE;

	box = mailbox_alloc(ns->list, name, 0);
	if (client->mailbox != NULL &&
	    mailbox_backends_equal(box, client->mailbox)) {
		/* deleting selected mailbox. close it first */
		client_search_updates_free(client);
		mailbox_free(&client->mailbox);
		disconnect = TRUE;
	}

	if (mailbox_delete(box) == 0)
		client_send_tagline(cmd, "OK Delete completed.");
	else {
		errstr = mailbox_get_last_error(box, &error);
		if (error != MAIL_ERROR_EXISTS)
			client_send_storage_error(cmd, mailbox_get_storage(box));
		else {
			/* mailbox has children */
			client_send_tagline(cmd, t_strdup_printf("NO %s", errstr));
		}
	}
	mailbox_free(&box);

	if (disconnect) {
		client_disconnect_with_error(cmd->client,
			"Selected mailbox was deleted, have to disconnect.");
	}
	return TRUE;
}
