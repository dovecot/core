/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "commands.h"

int cmd_list_full(Client *client, int subscribed);

int cmd_lsub(Client *client)
{
	return cmd_list_full(client, TRUE);
}
