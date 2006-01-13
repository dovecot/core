/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "commands.h"

bool cmd_login(struct client_command_context *cmd)
{
	client_send_tagline(cmd, "OK Already logged in.");
	return TRUE;
}
