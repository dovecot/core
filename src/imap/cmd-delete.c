/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "imap-commands.h"

bool cmd_delete(struct client_command_context *cmd)
{
	struct client *client = cmd->client;
	struct mail_namespace *ns;
	struct mailbox *box;
	const char *name, *client_error;
	enum mail_error error;
	bool disconnect = FALSE;

	/* <mailbox> */
	if (!client_read_string_args(cmd, 1, &name))
		return FALSE;

	ns = client_find_namespace(cmd, &name);
	if (ns == NULL)
		return TRUE;

	box = mailbox_alloc(ns->list, name, 0);
	mailbox_set_reason(box, "DELETE");
	if (mailbox_is_any_inbox(box)) {
		/* IMAP protocol allows this, but I think it's safer to
		   not allow it. */
		mailbox_free(&box);
		client_send_tagline(cmd, "NO INBOX can't be deleted.");
		return TRUE;
	}
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
		client_error = mailbox_get_last_error(box, &error);
		if (error != MAIL_ERROR_EXISTS)
			client_send_box_error(cmd, box);
		else {
			/* mailbox has children */
			client_send_tagline(cmd, t_strdup_printf("NO %s",
								 client_error));
		}
	}
	mailbox_free(&box);

	if (disconnect) {
		client_disconnect_with_error(cmd->client,
			"Selected mailbox was deleted, have to disconnect.");
	}
	return TRUE;
}
