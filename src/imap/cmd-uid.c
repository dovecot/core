/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "commands.h"

bool cmd_uid(struct client_command_context *cmd)
{
	struct command *command;
	const char *cmd_name;

	/* UID <command> <args> */
	cmd_name = imap_parser_read_word(cmd->parser);
	if (cmd_name == NULL)
		return FALSE;

	command = command_find(t_strconcat("UID ", cmd_name, NULL));
	cmd->cmd_flags = command->flags;
	cmd->func = command->func;

	if (cmd->func != NULL) {
		cmd->uid = TRUE;
		return cmd->func(cmd);
	} else {
		client_send_tagline(cmd, t_strconcat(
			"BAD Unknown UID command ", cmd_name, NULL));
		return TRUE;
	}
}
