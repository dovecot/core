/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "commands.h"

int cmd_noop(struct client *client)
{
	return cmd_sync(client, 0, "OK NOOP completed.");
}
