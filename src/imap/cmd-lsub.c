/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "commands.h"

int cmd_lsub(struct client *client)
{
	return _cmd_list_full(client, TRUE);
}
