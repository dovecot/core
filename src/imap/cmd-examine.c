/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "imap-common.h"
#include "imap-commands.h"

bool cmd_examine(struct client_command_context *cmd)
{
	return cmd_select_full(cmd, TRUE);
}
