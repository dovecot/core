/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "commands.h"

int cmd_uid(struct client *client)
{
	const char *cmd;

	/* UID <command> <args> */
	cmd = imap_parser_read_word(client->parser);
	if (cmd == NULL)
		return FALSE;

	client->cmd_func = command_find(t_strconcat("UID ", cmd, NULL));

	if (client->cmd_func != NULL) {
		client->cmd_uid = TRUE;
		return client->cmd_func(client);
	} else {
		client_send_tagline(client, t_strconcat(
			"BAD Unknown UID command ", cmd, NULL));
		return TRUE;
	}
}
