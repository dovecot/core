/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "commands.h"
#include "imap-util.h"

static void update_func(Mailbox *mailbox __attr_unused__, unsigned int seq,
			unsigned int uid __attr_unused__, MailFlags flags,
			const char *custom_flags[], void *user_data)
{
	Client *client = user_data;
	const char *str;

	t_push();
	str = imap_write_flags(flags, custom_flags);
	client_send_line(client,
			 t_strdup_printf("* %u FETCH (FLAGS (%s))", seq, str));
	t_pop();
}

static void update_func_uid(Mailbox *mailbox __attr_unused__, unsigned int seq,
			    unsigned int uid, MailFlags flags,
			    const char *custom_flags[], void *user_data)
{
	Client *client = user_data;
	const char *str;

	t_push();
	str = imap_write_flags(flags, custom_flags);
	client_send_line(client, t_strdup_printf(
		"* %u FETCH (FLAGS (%s) UID %u)", seq, str, uid));
	t_pop();
}

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
	ImapArgList *list, tmplist;
	MailFlags flags;
	ModifyType modify_type;
	MailFlagUpdateFunc func;
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

	if (args[2].type == IMAP_ARG_LIST)
		list = args[2].data.list;
	else {
		tmplist.next = NULL;
		tmplist.arg = args[2];
		list = &tmplist;
	}

	if (!client_parse_mail_flags(client, list, &flags, custflags))
		return TRUE;

	/* and update the flags */
	func = silent ? NULL :
		client->cmd_uid ? update_func_uid : update_func;
	if (client->mailbox->update_flags(client->mailbox, messageset,
					  client->cmd_uid, flags, custflags,
					  modify_type, func, client,
					  &all_found)) {
		/* NOTE: syncing isn't allowed here */
		client_send_tagline(client, all_found ? "OK Store completed." :
				    "NO Some messages were not found.");
	} else
		client_send_storage_error(client);

	return TRUE;
}
