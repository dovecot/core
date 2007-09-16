/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "commands.h"

bool cmd_examine(struct client_command_context *cmd)
{
	return cmd_select_full(cmd, TRUE);
}
