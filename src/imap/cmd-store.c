/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "commands.h"

static int get_modify_type(struct client *client, const char *item,
			   enum modify_type *modify_type, int *silent)
{
	if (*item == '+') {
		*modify_type = MODIFY_ADD;
		item++;
	} else if (*item == '-') {
		*modify_type = MODIFY_REMOVE;
		item++;
	} else {
		*modify_type = MODIFY_REPLACE;
	}

	if (strncasecmp(item, "FLAGS", 5) != 0) {
		client_send_tagline(client, t_strconcat(
			"NO Invalid item ", item, NULL));
		return FALSE;
	}

	*silent = strcasecmp(item+5, ".SILENT") == 0;
	if (!*silent && item[5] != '\0') {
		client_send_tagline(client, t_strconcat(
			"NO Invalid item ", item, NULL));
		return FALSE;
	}

	return TRUE;
}

int cmd_store(struct client *client)
{
	struct imap_arg *args;
	struct mail_full_flags flags;
	enum modify_type modify_type;
	const char *messageset, *item;
	int silent, all_found;

	if (!client_read_args(client, 0, 0, &args))
		return FALSE;

	if (!client_verify_open_mailbox(client))
		return TRUE;

	/* validate arguments */
	messageset = imap_arg_string(&args[0]);
	item = imap_arg_string(&args[1]);

	if (messageset == NULL || item == NULL) {
		client_send_command_error(client, "Invalid STORE arguments.");
		return TRUE;
	}

	if (!get_modify_type(client, item, &modify_type, &silent))
		return TRUE;

	if (args[2].type == IMAP_ARG_LIST) {
		if (!client_parse_mail_flags(client,
					     IMAP_ARG_LIST(&args[2])->args,
					     &flags))
			return TRUE;
	} else {
		if (!client_parse_mail_flags(client, args+2, &flags))
			return TRUE;
	}

	/* and update the flags */
	client->sync_flags_send_uid = client->cmd_uid;
	if (client->mailbox->update_flags(client->mailbox, messageset,
					  client->cmd_uid, &flags,
					  modify_type, !silent, &all_found)) {
		/* NOTE: syncing isn't allowed here */
		client_sync_without_expunges(client);
		client_send_tagline(client, all_found ? "OK Store completed." :
				    "NO Some of the messages no longer exist.");
	} else {
		client_send_storage_error(client);
	}

	client->sync_flags_send_uid = FALSE;
	return TRUE;
}
