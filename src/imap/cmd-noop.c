/* Copyright (c) 2002-2008 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "commands.h"

bool cmd_noop(struct client_command_context *cmd)
{
	return cmd_sync(cmd, 0, IMAP_SYNC_FLAG_SAFE, "OK NOOP completed.");
}
