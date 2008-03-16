/* Copyright (c) 2002-2008 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "commands.h"
#include "imap-expunge.h"

static void cmd_close_finish(struct client *client)
{
	if (mailbox_close(&client->mailbox) < 0) {
		client_send_untagged_storage_error(client,
			mailbox_get_storage(client->mailbox));
	}
	client_update_mailbox_flags(client, NULL);
	client->changing_mailbox = FALSE;
}

static bool cmd_close_callback(struct client_command_context *cmd)
{
	struct mailbox_status status;

	mailbox_get_status(cmd->client->mailbox,
			   STATUS_HIGHESTMODSEQ, &status);
	cmd_close_finish(cmd->client);
	client_send_tagline(cmd, t_strdup_printf(
		"OK [HIGHESTMODSEQ %llu] Close completed.",
		(unsigned long long)status.highest_modseq));
	return TRUE;
}

bool cmd_close(struct client_command_context *cmd)
{
	struct client *client = cmd->client;
	struct mailbox *mailbox = client->mailbox;
	struct mail_storage *storage;
	int ret;

	if (!client_verify_open_mailbox(cmd))
		return TRUE;

	i_assert(!client->changing_mailbox);
	client->changing_mailbox = TRUE;

	storage = mailbox_get_storage(mailbox);
	if ((ret = imap_expunge(mailbox, NULL)) < 0)
		client_send_untagged_storage_error(client, storage);

	if ((client->enabled_features & MAILBOX_FEATURE_QRESYNC) != 0 &&
	    ret > 0) {
		/* we expunged something. since we're sending updated
		   HIGHESTMODSEQ make sure the client sees all changes up to
		   it by syncing the mailbox one last time. We wouldn't need
		   to include our own expunge in there, but it's too much
		   trouble to hide it. */
		return cmd_sync_callback(cmd, 0, IMAP_SYNC_FLAG_SAFE,
					 cmd_close_callback);
	} else {
		if (mailbox_sync(mailbox, 0, 0, NULL) < 0)
			client_send_untagged_storage_error(client, storage);
		cmd_close_finish(client);
		client_send_tagline(cmd, "OK Close completed.");
		return TRUE;
	}
}
