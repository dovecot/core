/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "commands.h"

int cmd_close(Client *client)
{
	if (!client_verify_open_mailbox(client))
		return TRUE;

	/* Ignore expunge errors - we can't really do anything about it */
	(void)client->mailbox->expunge(client->mailbox);

	client->mailbox->close(client->mailbox);
	client->mailbox = NULL;

	client_send_tagline(client, "OK Close completed.");
	return TRUE;
}
