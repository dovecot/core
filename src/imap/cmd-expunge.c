/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "commands.h"

int cmd_expunge(Client *client)
{
	if (!client_verify_open_mailbox(client))
		return TRUE;

	if (client_sync_and_expunge_mailbox(client))
		client_send_tagline(client, "OK Expunge completed.");
	else
		client_send_storage_error(client);

	return TRUE;
}
