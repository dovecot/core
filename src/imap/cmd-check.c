/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "commands.h"

bool cmd_check(struct client_command_context *cmd)
{
	if (!client_verify_open_mailbox(cmd))
		return TRUE;

	return cmd_sync(cmd, MAILBOX_SYNC_FLAG_FULL_READ |
			MAILBOX_SYNC_FLAG_FULL_WRITE, 0, "OK Check completed.");
}
