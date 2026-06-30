/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "imap-common.h"
#include "imap-commands.h"

bool cmd_lsub(struct client_command_context *cmd)
{
	return cmd_list_full(cmd, TRUE);
}
