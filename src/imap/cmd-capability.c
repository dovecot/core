/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "commands.h"
#include "str.h"

int cmd_capability(struct client_command_context *cmd)
{
	client_send_line(cmd->client,
			 t_strconcat("* CAPABILITY ",
				     str_c(capability_string), NULL));

	client_send_tagline(cmd, "OK Capability completed.");
	return TRUE;
}
