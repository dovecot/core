/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "commands.h"

int cmd_capability(struct client *client)
{
	client_send_line(client, "* CAPABILITY " CAPABILITY_STRING);

	client_sync_full(client);
	client_send_tagline(client, "OK Capability completed.");
	return TRUE;
}
