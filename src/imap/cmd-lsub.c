/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "commands.h"

bool cmd_lsub(struct client_command_context *cmd)
{
	return cmd_list_full(cmd, TRUE);
}
