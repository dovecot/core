/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "commands.h"

int cmd_examine(struct client_command_context *cmd)
{
	return _cmd_select_full(cmd, TRUE);
}
