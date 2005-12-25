/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "commands.h"

int cmd_noop(struct client_command_context *cmd)
{
	return cmd_sync(cmd, 0, 0, "OK NOOP completed.");
}
