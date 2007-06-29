/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "str.h"
#include "imap-quote.h"
#include "commands.h"
#include "imap-sync.h"

/* Returns status items, or -1 if error */
static enum mailbox_status_items
get_status_items(struct client_command_context *cmd,
		 const struct imap_arg *args)
{
	const char *item;
	enum mailbox_status_items items;

	items = 0;
	for (; args->type != IMAP_ARG_EOL; args++) {
		if (args->type != IMAP_ARG_ATOM) {
			/* list may contain only atoms */
			client_send_command_error(cmd,
				"Status list contains non-atoms.");
			return -1;
		}

		item = t_str_ucase(IMAP_ARG_STR(args));

		if (strcmp(item, "MESSAGES") == 0)
			items |= STATUS_MESSAGES;
		else if (strcmp(item, "RECENT") == 0)
			items |= STATUS_RECENT;
		else if (strcmp(item, "UIDNEXT") == 0)
			items |= STATUS_UIDNEXT;
		else if (strcmp(item, "UIDVALIDITY") == 0)
			items |= STATUS_UIDVALIDITY;
		else if (strcmp(item, "UNSEEN") == 0)
			items |= STATUS_UNSEEN;
		else {
			client_send_tagline(cmd, t_strconcat(
				"BAD Invalid status item ", item, NULL));
			return -1;
		}
	}

	return items;
}

static bool
get_mailbox_status(struct client *client, struct mail_storage *storage,
		   const char *mailbox, enum mailbox_status_items items,
		   struct mailbox_status *status)
{
	struct mailbox *box;
	bool failed = FALSE;

	if (client->mailbox != NULL &&
	    mailbox_equals(client->mailbox, storage, mailbox)) {
		/* this mailbox is selected */
		box = client->mailbox;
	} else {
		/* open the mailbox */
		box = mailbox_open(storage, mailbox, NULL, MAILBOX_OPEN_FAST |
				   MAILBOX_OPEN_READONLY |
				   MAILBOX_OPEN_KEEP_RECENT);
		if (box == NULL)
			return FALSE;

		if (imap_sync_nonselected(box, 0) < 0)
			failed = TRUE;
	}

	if (!failed)
		failed = mailbox_get_status(box, items, status) < 0;

	if (box != client->mailbox)
		mailbox_close(&box);

	return !failed;
}

bool cmd_status(struct client_command_context *cmd)
{
	struct client *client = cmd->client;
	const struct imap_arg *args;
	struct mailbox_status status;
	enum mailbox_status_items items;
	struct mail_storage *storage;
	const char *mailbox, *real_mailbox;
	string_t *str;

	/* <mailbox> <status items> */
	if (!client_read_args(cmd, 2, 0, &args))
		return FALSE;

	mailbox = real_mailbox = imap_arg_string(&args[0]);
	if (mailbox == NULL || args[1].type != IMAP_ARG_LIST) {
		client_send_command_error(cmd, "Status items must be list.");
		return TRUE;
	}

	/* get the items client wants */
	items = get_status_items(cmd, IMAP_ARG_LIST_ARGS(&args[1]));
	if (items == (enum mailbox_status_items)-1) {
		/* error */
		return TRUE;
	}

	storage = client_find_storage(cmd, &real_mailbox);
	if (storage == NULL)
		return TRUE;

	/* get status */
	if (!get_mailbox_status(client, storage, real_mailbox,
				items, &status)) {
		client_send_storage_error(cmd, storage);
		return TRUE;
	}

	str = t_str_new(128);
	str_append(str, "* STATUS ");
        imap_quote_append_string(str, mailbox, FALSE);
	str_append(str, " (");

	if (items & STATUS_MESSAGES)
		str_printfa(str, "MESSAGES %u ", status.messages);
	if (items & STATUS_RECENT)
		str_printfa(str, "RECENT %u ", status.recent);
	if (items & STATUS_UIDNEXT)
		str_printfa(str, "UIDNEXT %u ", status.uidnext);
	if (items & STATUS_UIDVALIDITY)
		str_printfa(str, "UIDVALIDITY %u ", status.uidvalidity);
	if (items & STATUS_UNSEEN)
		str_printfa(str, "UNSEEN %u ", status.unseen);

	if (items != 0)
		str_truncate(str, str_len(str)-1);
	str_append_c(str, ')');

	client_send_line(client, str_c(str));
	client_send_tagline(cmd, "OK Status completed.");

	return TRUE;
}
