/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "commands.h"
#include "imap-search.h"
#include "imap-expunge.h"

int cmd_uid_expunge(struct client *client)
{
	struct imap_arg *args;
	struct mail_search_arg *search_arg;
	const char *uidset;

	if (!client_read_args(client, 1, 0, &args))
		return FALSE;

	if (!client_verify_open_mailbox(client))
		return TRUE;

	uidset = imap_arg_string(&args[0]);
	if (uidset == NULL) {
		client_send_command_error(client, "Invalid arguments.");
		return TRUE;
	}

	search_arg = imap_search_get_arg(client, uidset, TRUE);
	if (search_arg == NULL)
		return TRUE;

	if (imap_expunge(client->mailbox, search_arg)) {
		return cmd_sync(client, MAILBOX_SYNC_FLAG_FULL,
				"OK Expunge completed.");
	} else {
		client_send_storage_error(client,
					  mailbox_get_storage(client->mailbox));
		return TRUE;
	}
}

int cmd_expunge(struct client *client)
{
	if (!client_verify_open_mailbox(client))
		return TRUE;

	if (imap_expunge(client->mailbox, NULL)) {
		return cmd_sync(client, MAILBOX_SYNC_FLAG_FULL,
				"OK Expunge completed.");
	} else {
		client_send_storage_error(client,
					  mailbox_get_storage(client->mailbox));
		return TRUE;
	}
}
