/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "commands.h"

int cmd_uid(Client *client)
{
	const char *cmd;

	/* UID <command> <args> */
	cmd = imap_parser_read_word(client->parser);
	if (cmd == NULL)
		return FALSE;

	client->cmd_func = NULL;
	switch (*cmd) {
	case 'c':
	case 'C':
		if (strcasecmp(cmd, "COPY") == 0)
			client->cmd_func = cmd_copy;
		break;
	case 'f':
	case 'F':
		if (strcasecmp(cmd, "FETCH") == 0)
			client->cmd_func = cmd_fetch;
		break;
	case 's':
	case 'S':
		if (strcasecmp(cmd, "STORE") == 0)
			client->cmd_func = cmd_store;
		else if (strcasecmp(cmd, "SEARCH") == 0)
			client->cmd_func = cmd_search;
		break;
	}

	if (client->cmd_func != NULL) {
		client->cmd_uid = TRUE;
		return client->cmd_func(client);
	} else {
		client_send_tagline(client, t_strconcat(
			"BAD Unknown UID command ", cmd, NULL));
		return TRUE;
	}
}
