/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "commands.h"

int cmd_subscribe_full(Client *client, int subscribe);

int cmd_unsubscribe(Client *client)
{
	return cmd_subscribe_full(client, FALSE);
}
