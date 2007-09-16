/* Copyright (c) 2002-2007 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "commands.h"

bool cmd_noop(struct client_command_context *cmd)
{
	return cmd_sync(cmd, 0, 0, "OK NOOP completed.");
}
