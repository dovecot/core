/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "commands.h"

int cmd_copy(Client *client)
{
	Mailbox *destbox;
	const char *messageset, *mailbox;

	/* <message set> <mailbox> */
	if (!client_read_string_args(client, 2, &messageset, &mailbox))
		return FALSE;

	if (!client_verify_mailbox_name(client, mailbox, TRUE))
		return TRUE;

	/* open the destination mailbox */
	if (!client_verify_mailbox_name(client, mailbox, TRUE))
		return TRUE;

	destbox = client->storage->open_mailbox(client->storage,
						mailbox, FALSE);
	if (destbox == NULL) {
		client_send_storage_error(client);
		return TRUE;
	}

	/* copy the mail */
	if (client->mailbox->copy(client->mailbox, destbox,
				  messageset, client->cmd_uid)) {
                client_sync_mailbox(client);
		client_send_tagline(client, "OK Copy completed.");
	} else
		client_send_storage_error(client);

	destbox->close(destbox);
	return TRUE;
}
