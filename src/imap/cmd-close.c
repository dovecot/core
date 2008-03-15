/* Copyright (c) 2002-2008 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "commands.h"
#include "imap-expunge.h"

bool cmd_close(struct client_command_context *cmd)
{
	struct client *client = cmd->client;
	struct mailbox *mailbox = client->mailbox;
	struct mail_storage *storage;
	struct mailbox_status status;
	bool show_highestmodseq;

	if (!client_verify_open_mailbox(cmd))
		return TRUE;

	storage = mailbox_get_storage(mailbox);
	client->mailbox = NULL;

	show_highestmodseq =
		(cmd->client->enabled_features & MAILBOX_FEATURE_QRESYNC) != 0;

	if (!imap_expunge(mailbox, NULL))
		client_send_untagged_storage_error(client, storage);
	else if (mailbox_sync(mailbox, 0, !show_highestmodseq ? 0 :
			      STATUS_HIGHESTMODSEQ, &status) < 0)
		client_send_untagged_storage_error(client, storage);

	if (mailbox_close(&mailbox) < 0)
                client_send_untagged_storage_error(client, storage);
	client_update_mailbox_flags(client, NULL);

	if (!show_highestmodseq)
		client_send_tagline(cmd, "OK Close completed.");
	else {
		client_send_tagline(cmd, t_strdup_printf(
			"OK [HIGHESTMODSEQ %llu] Close completed.",
			(unsigned long long)status.highest_modseq));
	}
	return TRUE;
}
