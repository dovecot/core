/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "commands.h"

int cmd_check(struct client *client)
{
	if (!client_verify_open_mailbox(client))
		return TRUE;

	/* we don't need this command, but sync the mailbox anyway. */
	client_sync_full(client);
	client_send_tagline(client, "OK Check completed.");
	return TRUE;
}
