/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "commands.h"

int cmd_check(struct client *client)
{
	if (!client_verify_open_mailbox(client))
		return TRUE;

	return cmd_sync(client, 0, "OK Check completed.");
}
