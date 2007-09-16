/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "commands.h"

bool cmd_unsubscribe(struct client_command_context *cmd)
{
	return cmd_subscribe_full(cmd, FALSE);
}
