/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "commands.h"

static int get_modify_type(Client *client, const char *item,
			   ModifyType *modify_type, int *silent)
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

int cmd_store(Client *client)
{
	ImapArg *args;
	MailFlags flags;
	ModifyType modify_type;
	const char *custflags[MAIL_CUSTOM_FLAGS_COUNT];
	const char *messageset, *item;
	int silent, all_found;

	if (!client_read_args(client, 3, 0, &args))
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
					     IMAP_ARG_LIST(&args[2])->size,
					     &flags, custflags))
			return TRUE;
	} else {
		if (!client_parse_mail_flags(client, &args[2], 1,
					     &flags, custflags))
			return TRUE;
	}

	/* and update the flags */
	client->sync_flags_send_uid = client->cmd_uid;
	if (client->mailbox->update_flags(client->mailbox, messageset,
					  client->cmd_uid, flags, custflags,
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
