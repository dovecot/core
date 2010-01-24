/* Copyright (c) 2008-2010 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "imap-commands.h"

static bool client_search_update_cancel(struct client *client, const char *tag)
{
	struct imap_search_update *update;
	unsigned int idx;

	update = client_search_update_lookup(client, tag, &idx);
	if (update == NULL)
		return FALSE;

	i_free(update->tag);
	mailbox_search_result_free(&update->result);
	array_delete(&client->search_updates, idx, 1);
	return TRUE;
}

bool cmd_cancelupdate(struct client_command_context *cmd)
{
	const struct imap_arg *args;
	const char *str;
	unsigned int i;

	if (!client_read_args(cmd, 0, 0, &args))
		return FALSE;

	for (i = 0; args[i].type == IMAP_ARG_STRING; i++) ;
	if (args[i].type != IMAP_ARG_EOL || i == 0) {
		client_send_tagline(cmd, "BAD Invalid parameters.");
		return TRUE;
	}
	for (i = 0; args[i].type == IMAP_ARG_STRING; i++) {
		str = IMAP_ARG_STR_NONULL(&args[i]);
		if (!client_search_update_cancel(cmd->client, str)) {
			client_send_tagline(cmd, "BAD Unknown tag.");
			return TRUE;
		}
	}
	client_send_tagline(cmd, "OK Updates cancelled.");
	return TRUE;
}
