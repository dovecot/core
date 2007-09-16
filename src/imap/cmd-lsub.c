/* Copyright (c) 2002-2007 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "commands.h"

bool cmd_lsub(struct client_command_context *cmd)
{
	return cmd_list_full(cmd, TRUE);
}
