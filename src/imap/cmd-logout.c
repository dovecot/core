/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "commands.h"

int cmd_logout(Client *client)
{
	client_send_line(client, "* BYE Logging out");

	if (client->mailbox != NULL) {
		/* this could be done at client_disconnect() as well,
		   but eg. mbox rewrite takes a while so the waiting is
		   better to happen before "OK" message. */
		client->mailbox->close(client->mailbox);
		client->mailbox = NULL;
	}

	client_send_tagline(client, "OK Logout completed.");
	client_disconnect(client);
	return TRUE;
}
