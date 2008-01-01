/* Copyright (c) 2002-2008 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "commands.h"

bool cmd_unsubscribe(struct client_command_context *cmd)
{
	return cmd_subscribe_full(cmd, FALSE);
}
