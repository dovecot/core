/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "commands.h"

int cmd_examine(Client *client)
{
	return _cmd_select_full(client, TRUE);
}
