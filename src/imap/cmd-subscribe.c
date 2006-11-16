/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "commands.h"

bool _cmd_subscribe_full(struct client_command_context *cmd, bool subscribe)
{
        struct mail_storage *storage;
	struct mailbox_list *list;
	const char *mailbox, *verify_name;

	/* <mailbox> */
	if (!client_read_string_args(cmd, 1, &mailbox))
		return FALSE;

	verify_name = mailbox;
	if ((client_workarounds & WORKAROUND_TB_EXTRA_MAILBOX_SEP) != 0 &&
	    *mailbox != '\0') {
		/* verify the validity without the trailing '/' */
		storage = client_find_storage(cmd, &mailbox);
		if (storage == NULL)
			return TRUE;

		if (mailbox[strlen(mailbox)-1] ==
		    mail_storage_get_hierarchy_sep(storage))
			verify_name = t_strndup(mailbox, strlen(mailbox)-1);
	} else {
		storage = client_find_storage(cmd, &mailbox);
		if (storage == NULL)
			return TRUE;
	}

	if (!client_verify_mailbox_name(cmd, verify_name, subscribe, FALSE))
		return TRUE;

	list = mail_storage_get_list(storage);
	if (mailbox_list_set_subscribed(list, mailbox, subscribe) < 0)
		client_send_storage_error(cmd, storage);
	else {
		client_send_tagline(cmd, subscribe ?
				    "OK Subscribe completed." :
				    "OK Unsubscribe completed.");
	}
	return TRUE;
}

bool cmd_subscribe(struct client_command_context *cmd)
{
	return _cmd_subscribe_full(cmd, TRUE);
}
