/* Copyright (c) 2002-2007 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "commands.h"
#include "imap-sync.h"
#include "imap-status.h"

bool cmd_status(struct client_command_context *cmd)
{
	struct client *client = cmd->client;
	const struct imap_arg *args;
	struct mailbox_status status;
	enum mailbox_status_items items;
	struct mail_storage *storage;
	const char *mailbox, *real_mailbox;

	/* <mailbox> <status items> */
	if (!client_read_args(cmd, 2, 0, &args))
		return FALSE;

	mailbox = real_mailbox = imap_arg_string(&args[0]);
	if (mailbox == NULL || args[1].type != IMAP_ARG_LIST) {
		client_send_command_error(cmd, "Status items must be list.");
		return TRUE;
	}

	/* get the items client wants */
	if (imap_status_parse_items(cmd, IMAP_ARG_LIST_ARGS(&args[1]),
				    &items) < 0)
		return TRUE;

	storage = client_find_storage(cmd, &real_mailbox);
	if (storage == NULL)
		return TRUE;

	if (!imap_status_get(client, storage, real_mailbox, items, &status)) {
		client_send_storage_error(cmd, storage);
		return TRUE;
	}

	imap_status_send(client, mailbox, items, &status);
	client_send_tagline(cmd, "OK Status completed.");

	return TRUE;
}
