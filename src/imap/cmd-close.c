/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "commands.h"

int cmd_close(Client *client)
{
	if (!client_verify_open_mailbox(client))
		return TRUE;

	if (!client->mailbox->expunge(client->mailbox, FALSE)) {
		/* just warn about the error */
		client_send_tagline(client, t_strconcat("* NO ",
			client->storage->get_last_error(client->storage),
			NULL));
	}

	client->mailbox->close(client->mailbox);
	client->mailbox = NULL;

	client_send_tagline(client, "OK Close completed.");
	return TRUE;
}
