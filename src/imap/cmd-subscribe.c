/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "commands.h"

int cmd_subscribe_full(Client *client, int subscribe)
{
	const char *mailbox;

	/* <mailbox> */
	if (!client_read_string_args(client, 1, &mailbox))
		return FALSE;

	if (!client_verify_mailbox_name(client, mailbox, subscribe, FALSE))
		return TRUE;

	if (client->storage->set_subscribed(client->storage,
					    mailbox, subscribe)) {
		client_send_tagline(client, subscribe ?
				    "OK Subscribe completed." :
				    "OK Unsubscribe completed.");
	} else {
		client_send_storage_error(client);
	}

	return TRUE;
}

int cmd_subscribe(Client *client)
{
	return cmd_subscribe_full(client, TRUE);
}
