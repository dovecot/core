/* Copyright (c) 2002-2017 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "imap-commands.h"
#include "imap-expunge.h"

bool cmd_close(struct client_command_context *cmd)
{
	struct client *client = cmd->client;
	struct mailbox *mailbox = client->mailbox;
	struct mail_storage *storage;
	const char *errstr, *tagged_reply = "OK Close completed.";
	enum mail_error error = MAIL_ERROR_NONE;

	if (!client_verify_open_mailbox(cmd))
		return TRUE;

	i_assert(client->mailbox_change_lock == NULL);

	storage = mailbox_get_storage(mailbox);
	if (imap_expunge(mailbox, NULL, &client->expunged_count) < 0) {
		errstr = mailbox_get_last_error(mailbox, &error);
		if (error != MAIL_ERROR_PERM)
			client_send_untagged_storage_error(client, storage);
		else {
			tagged_reply = t_strdup_printf(
				"OK Closed without expunging: %s", errstr);
		}
	}
	if (mailbox_sync(mailbox, 0) < 0)
		client_send_untagged_storage_error(client, storage);

	imap_client_close_mailbox(client);
	client_send_tagline(cmd, tagged_reply);
	return TRUE;
}
