/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "commands.h"

int cmd_authenticate(struct client_command_context *cmd)
{
	client_send_tagline(cmd, "OK Already authenticated.");
	return TRUE;
}
