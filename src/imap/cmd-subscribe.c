/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "commands.h"

int _cmd_subscribe_full(struct client *client, int subscribe)
{
        struct mail_storage *storage;
	const char *mailbox;

	/* <mailbox> */
	if (!client_read_string_args(client, 1, &mailbox))
		return FALSE;

	if (!client_verify_mailbox_name(client, mailbox, subscribe, FALSE))
		return TRUE;

	storage = client_find_storage(client, mailbox);
	if (storage == NULL)
		return FALSE;

	if (storage->set_subscribed(storage, mailbox, subscribe)) {
		client_send_tagline(client, subscribe ?
				    "OK Subscribe completed." :
				    "OK Unsubscribe completed.");
	} else {
		client_send_storage_error(client, storage);
	}

	return TRUE;
}

int cmd_subscribe(struct client *client)
{
	return _cmd_subscribe_full(client, TRUE);
}
