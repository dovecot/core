/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "commands.h"

int cmd_unsubscribe(struct client_command_context *cmd)
{
	return _cmd_subscribe_full(cmd, FALSE);
}
