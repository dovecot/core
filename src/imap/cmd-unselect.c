/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "commands.h"

int cmd_unselect(struct client *client)
{
	if (!client_verify_open_mailbox(client))
		return TRUE;

	if (!client->mailbox->close(client->mailbox))
		client_send_closing_mailbox_error(client);

	client->mailbox = NULL;

	client_send_tagline(client, "OK Unselect completed.");
	return TRUE;
}
