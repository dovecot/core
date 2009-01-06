/* Copyright (c) 2002-2009 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "commands.h"

bool cmd_examine(struct client_command_context *cmd)
{
	return cmd_select_full(cmd, TRUE);
}
