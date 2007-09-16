/* Copyright (c) 2002-2007 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "commands.h"

bool cmd_check(struct client_command_context *cmd)
{
	if (!client_verify_open_mailbox(cmd))
		return TRUE;

	return cmd_sync(cmd, MAILBOX_SYNC_FLAG_FULL_READ |
			MAILBOX_SYNC_FLAG_FULL_WRITE, 0, "OK Check completed.");
}
