/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "commands.h"

int cmd_login(Client *client)
{
	client_send_tagline(client, "OK Already logged in.");
	return TRUE;
}
