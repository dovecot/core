/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "imap-commands.h"
#include "str.h"

bool cmd_capability(struct client_command_context *cmd)
{
	client_send_line(cmd->client, t_strconcat(
		"* CAPABILITY ", client_get_capability(cmd->client), NULL));

	client_send_tagline(cmd, "OK Capability completed.");
	return TRUE;
}
