/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "commands.h"

int cmd_authenticate(struct client *client)
{
	client_send_tagline(client, "OK Already authenticated.");
	return TRUE;
}
