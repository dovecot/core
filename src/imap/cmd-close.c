/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "commands.h"
#include "imap-expunge.h"

int cmd_close(struct client *client)
{
	struct mailbox *mailbox = client->mailbox;
	struct mail_storage *storage;

	if (!client_verify_open_mailbox(client))
		return TRUE;

	storage = mailbox_get_storage(mailbox);
	client->mailbox = NULL;

	if (!mailbox_is_readonly(mailbox)) {
		if (!imap_expunge(mailbox, NULL))
			client_send_untagged_storage_error(client, storage);
	}

	if (mailbox_close(mailbox) < 0)
                client_send_untagged_storage_error(client, storage);

	client_send_tagline(client, "OK Close completed.");
	return TRUE;
}
