/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "commands.h"

int cmd_check(struct client *client)
{
	if (!client_verify_open_mailbox(client))
		return TRUE;

	return cmd_sync(client, MAILBOX_SYNC_FLAG_FULL_READ |
			MAILBOX_SYNC_FLAG_FULL_WRITE, "OK Check completed.");
}
