/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "commands.h"

int cmd_copy(struct client *client)
{
	struct mailbox *destbox;
	const char *messageset, *mailbox;
	int ret;

	/* <message set> <mailbox> */
	if (!client_read_string_args(client, 2, &messageset, &mailbox))
		return FALSE;

	if (!client_verify_mailbox_name(client, mailbox, TRUE, FALSE))
		return TRUE;

	/* open the destination mailbox */
	if (!client_verify_mailbox_name(client, mailbox, TRUE, FALSE))
		return TRUE;

	destbox = client->storage->open_mailbox(client->storage,
						mailbox, FALSE, TRUE);
	if (destbox == NULL) {
		client_send_storage_error(client);
		return TRUE;
	}

	/* copy the mail */
	ret = client->mailbox->copy(client->mailbox, destbox,
				    messageset, client->cmd_uid);

	if (ret) {
		client_sync_full_fast(client);
		client_send_tagline(client, "OK Copy completed.");
	} else {
		/* if COPY fails because of expunges they'll get synced here */
		client_sync_full(client);
		client_send_storage_error(client);
	}

	destbox->close(destbox);
	return TRUE;
}
