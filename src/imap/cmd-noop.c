/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "commands.h"

int cmd_noop(struct client *client)
{
	client_sync_full(client);
	client_send_tagline(client, "OK NOOP completed.");
	return TRUE;
}
