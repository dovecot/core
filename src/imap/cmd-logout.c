/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "ostream.h"
#include "commands.h"

int cmd_logout(struct client_command_context *cmd)
{
	struct client *client = cmd->client;

	client_send_line(client, "* BYE Logging out");
	o_stream_uncork(client->output);

	if (client->mailbox != NULL) {
		/* this could be done at client_disconnect() as well,
		   but eg. mbox rewrite takes a while so the waiting is
		   better to happen before "OK" message. */
		mailbox_close(client->mailbox);
		client->mailbox = NULL;
	}

	client_send_tagline(cmd, "OK Logout completed.");
	client_disconnect(client);
	return TRUE;
}
