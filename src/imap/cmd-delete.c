/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "commands.h"

int cmd_delete(struct client *client)
{
	struct mail_storage *storage;
	struct mailbox *mailbox;
	const char *name;

	/* <mailbox> */
	if (!client_read_string_args(client, 1, &name))
		return FALSE;

	if (strcasecmp(name, "INBOX") == 0) {
		/* INBOX can't be deleted */
		client_send_tagline(client, "NO INBOX can't be deleted.");
		return TRUE;
	}

	mailbox = client->mailbox;
	if (mailbox != NULL && strcmp(mailbox_get_name(mailbox), name) == 0) {
		/* deleting selected mailbox. close it first */
		storage = mailbox_get_storage(mailbox);
		client->mailbox = NULL;

		if (mailbox_close(mailbox) < 0)
			client_send_untagged_storage_error(client, storage);
	} else {
		storage = client_find_storage(client, name);
		if (storage == NULL)
			return TRUE;
	}

	if (mail_storage_mailbox_delete(storage, name) < 0)
		client_send_storage_error(client, storage);
	else
		client_send_tagline(client, "OK Delete completed.");
	return TRUE;
}
