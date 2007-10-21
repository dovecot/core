/* Copyright (c) 2002-2007 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "commands.h"
#include "mail-namespace.h"

bool cmd_subscribe_full(struct client_command_context *cmd, bool subscribe)
{
	struct mail_namespace *ns;
        struct mail_storage *storage;
	struct mailbox_list *list;
	const char *mailbox, *verify_name;

	/* <mailbox> */
	if (!client_read_string_args(cmd, 1, &mailbox))
		return FALSE;

	verify_name = mailbox;
	ns = mail_namespace_find_subscribable(cmd->client->namespaces,
					      &mailbox);
	if (ns == NULL) {
		client_send_tagline(cmd, "NO Unknown namespace.");
		return TRUE;
	}
	storage = ns->storage;

	if ((client_workarounds & WORKAROUND_TB_EXTRA_MAILBOX_SEP) != 0 &&
	    *mailbox != '\0' && mailbox[strlen(mailbox)-1] ==
	    mail_storage_get_hierarchy_sep(storage)) {
		/* verify the validity without the trailing '/' */
		verify_name = t_strndup(verify_name, strlen(verify_name)-1);
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
	return cmd_subscribe_full(cmd, TRUE);
}
