/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "commands.h"
#include "imap-expunge.h"

int cmd_close(struct client *client)
{
	struct mailbox *mailbox = client->mailbox;

	if (!client_verify_open_mailbox(client))
		return TRUE;

	client->mailbox = NULL;

	if (!mailbox->is_readonly(mailbox)) {
		if (!imap_expunge(mailbox, FALSE))
			client_send_untagged_storage_error(client);
	}

	if (!mailbox->close(mailbox))
                client_send_untagged_storage_error(client);

	client_send_tagline(client, "OK Close completed.");
	return TRUE;
}
