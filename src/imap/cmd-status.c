/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "str.h"
#include "commands.h"

/* Returns status items, or -1 if error */
static enum mailbox_status_items
get_status_items(struct client *client, struct imap_arg *args)
{
	const char *item;
	enum mailbox_status_items items;

	items = 0;
	for (; args->type != IMAP_ARG_EOL; args++) {
		if (args->type != IMAP_ARG_ATOM) {
			/* list may contain only atoms */
			client_send_command_error(client,
				"Status list contains non-atoms.");
			return -1;
		}

		item = str_ucase(IMAP_ARG_STR(args));

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
			client_send_tagline(client, t_strconcat(
				"BAD Invalid status item ", item, NULL));
			return -1;
		}
	}

	return items;
}

static int mailbox_name_equals(const char *box1, const char *box2)
{
	if (strcmp(box1, box2) == 0)
		return TRUE;

	return strcasecmp(box1, "INBOX") == 0 && strcasecmp(box2, "INBOX") == 0;
}

static int get_mailbox_status(struct client *client, const char *mailbox,
			      enum mailbox_status_items items,
			      struct mailbox_status *status)
{
	struct mailbox *box;
	int failed;

	if (client->mailbox != NULL &&
	    mailbox_name_equals(client->mailbox->name, mailbox)) {
		/* this mailbox is selected */
		box = client->mailbox;
	} else {
		/* open the mailbox */
		box = client->storage->open_mailbox(client->storage,
						    mailbox, FALSE, TRUE);
		if (box == NULL)
			return FALSE;
	}

	failed = !box->get_status(box, items, status);

	if (box != client->mailbox)
		box->close(box);

	return !failed;
}

int cmd_status(struct client *client)
{
	struct imap_arg *args;
	struct mailbox_status status;
	enum mailbox_status_items items;
	const char *mailbox;
	string_t *str;

	/* <mailbox> <status items> */
	if (!client_read_args(client, 2, 0, &args))
		return FALSE;

	mailbox = imap_arg_string(&args[0]);
	if (mailbox == NULL || args[1].type != IMAP_ARG_LIST) {
		client_send_command_error(client, "Status items must be list.");
		return TRUE;
	}

	/* get the items client wants */
	items = get_status_items(client, IMAP_ARG_LIST(&args[1])->args);
	if (items == (enum mailbox_status_items)-1) {
		/* error */
		return TRUE;
	}

	/* get status */
	if (!get_mailbox_status(client, mailbox, items, &status)) {
		client_send_storage_error(client);
		return TRUE;
	}

	str = t_str_new(128);
	str_printfa(str, "* STATUS %s (", mailbox);
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
	client_send_tagline(client, "OK Status completed.");

	return TRUE;
}
