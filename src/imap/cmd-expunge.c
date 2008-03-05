/* Copyright (c) 2002-2008 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "commands.h"
#include "imap-search.h"
#include "imap-expunge.h"

bool cmd_uid_expunge(struct client_command_context *cmd)
{
	struct client *client = cmd->client;
	const struct imap_arg *args;
	struct mail_search_arg *search_arg;
	const char *uidset;

	if (!client_read_args(cmd, 1, 0, &args))
		return FALSE;

	if (!client_verify_open_mailbox(cmd))
		return TRUE;

	uidset = imap_arg_string(&args[0]);
	if (uidset == NULL) {
		client_send_command_error(cmd, "Invalid arguments.");
		return TRUE;
	}

	search_arg = imap_search_get_arg(cmd, uidset, TRUE);
	if (search_arg == NULL)
		return TRUE;

	if (imap_expunge(client->mailbox, search_arg)) {
		return cmd_sync(cmd, 0, IMAP_SYNC_FLAG_SAFE,
				"OK Expunge completed.");
	} else {
		client_send_storage_error(cmd,
					  mailbox_get_storage(client->mailbox));
		return TRUE;
	}
}

static bool cmd_expunge_callback(struct client_command_context *cmd)
{
	if (cmd->client->sync_seen_deletes) {
		/* Outlook workaround: session 1 set \Deleted flag and
		   session 2 tried to expunge without having seen it yet.
		   expunge again. */
		return cmd_expunge(cmd);
	}

	client_send_tagline(cmd, "OK Expunge completed.");
	return TRUE;
}

bool cmd_expunge(struct client_command_context *cmd)
{
	struct client *client = cmd->client;

	if (!client_verify_open_mailbox(cmd))
		return TRUE;

	cmd->client->sync_seen_deletes = FALSE;
	if (imap_expunge(client->mailbox, NULL)) {
		return cmd_sync_callback(cmd, 0, IMAP_SYNC_FLAG_SAFE,
					 cmd_expunge_callback);
	} else {
		client_send_storage_error(cmd,
					  mailbox_get_storage(client->mailbox));
		return TRUE;
	}
}
