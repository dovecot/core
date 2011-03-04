/* Copyright (c) 2008-2011 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "imap-id.h"

bool cmd_id(struct client_command_context *cmd)
{
	const struct imap_settings *set = cmd->client->set;
	const struct imap_arg *args;
	const char *value;

	if (!client_read_args(cmd, 0, 0, &args))
		return FALSE;

	if (!cmd->client->id_logged) {
		cmd->client->id_logged = TRUE;
		value = imap_id_args_get_log_reply(args, set->imap_id_log);
		if (value != NULL)
			i_info("ID sent: %s", value);
	}

	client_send_line(cmd->client, t_strdup_printf(
		"* ID %s", imap_id_reply_generate(set->imap_id_send)));
	client_send_tagline(cmd, "OK ID completed.");
	return TRUE;
}

