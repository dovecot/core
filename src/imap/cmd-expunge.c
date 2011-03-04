/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "imap-commands.h"
#include "imap-search-args.h"
#include "imap-expunge.h"

static bool cmd_expunge_callback(struct client_command_context *cmd)
{
	if (cmd->client->sync_seen_deletes && !cmd->uid) {
		/* Outlook workaround: session 1 set \Deleted flag and
		   session 2 tried to expunge without having seen it yet.
		   expunge again. MAILBOX_TRANSACTION_FLAG_REFRESH should
		   have caught this already if index files are used. */
		return cmd_expunge(cmd);
	}

	client_send_tagline(cmd, "OK Expunge completed.");
	return TRUE;
}

static bool cmd_expunge_finish(struct client_command_context *cmd,
			       struct mail_search_args *search_args)
{
	struct client *client = cmd->client;

	if (imap_expunge(client->mailbox, search_args == NULL ? NULL :
			 search_args->args) < 0) {
		client_send_storage_error(cmd,
					  mailbox_get_storage(client->mailbox));
		return TRUE;
	}
	if (search_args != NULL)
		mail_search_args_unref(&search_args);

	client->sync_seen_deletes = FALSE;
	client->sync_seen_expunges = FALSE;
	if ((client->enabled_features & MAILBOX_FEATURE_QRESYNC) != 0) {
		return cmd_sync(cmd, MAILBOX_SYNC_FLAG_EXPUNGE,
				IMAP_SYNC_FLAG_SAFE, "OK Expunge completed.");
	} else {
		return cmd_sync_callback(cmd, MAILBOX_SYNC_FLAG_EXPUNGE,
					 IMAP_SYNC_FLAG_SAFE,
					 cmd_expunge_callback);
	}
}

bool cmd_uid_expunge(struct client_command_context *cmd)
{
	const struct imap_arg *args;
	struct mail_search_args *search_args;
	const char *uidset;
	int ret;

	if (!client_read_args(cmd, 1, 0, &args))
		return FALSE;

	if (!client_verify_open_mailbox(cmd))
		return TRUE;

	if (!imap_arg_get_astring(&args[0], &uidset)) {
		client_send_command_error(cmd, "Invalid arguments.");
		return TRUE;
	}

	ret = imap_search_get_seqset(cmd, uidset, TRUE, &search_args);
	if (ret <= 0)
		return ret < 0;
	return cmd_expunge_finish(cmd, search_args);
}

bool cmd_expunge(struct client_command_context *cmd)
{
	if (!client_verify_open_mailbox(cmd))
		return TRUE;

	return cmd_expunge_finish(cmd, NULL);
}
