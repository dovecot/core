/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "commands.h"

int cmd_select_full(Client *client, int readonly);

int cmd_examine(Client *client)
{
	return cmd_select_full(client, TRUE);
}
