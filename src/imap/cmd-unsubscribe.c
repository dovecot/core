/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "commands.h"

int cmd_unsubscribe(Client *client)
{
	return _cmd_subscribe_full(client, FALSE);
}
