/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "commands.h"

int cmd_expunge(struct client *client)
{
	if (!client_verify_open_mailbox(client))
		return TRUE;

	if (client->mailbox->expunge(client->mailbox, TRUE))
		client_send_tagline(client, "OK Expunge completed.");
	else
		client_send_storage_error(client);

	return TRUE;
}
