/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "commands.h"

int cmd_noop(Client *client)
{
	client_sync_mailbox(client);
	client_send_tagline(client, "OK NOOP completed.");
	return TRUE;
}
