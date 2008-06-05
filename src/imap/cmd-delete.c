/* Copyright (c) 2002-2008 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "commands.h"

bool cmd_delete(struct client_command_context *cmd)
{
	struct client *client = cmd->client;
	struct mail_storage *storage;
	struct mailbox_list *list;
	struct mailbox *mailbox;
	const char *name;

	/* <mailbox> */
	if (!client_read_string_args(cmd, 1, &name))
		return FALSE;

	if (strcasecmp(name, "INBOX") == 0) {
		/* INBOX can't be deleted */
		client_send_tagline(cmd, "NO INBOX can't be deleted.");
		return TRUE;
	}

	mailbox = client->mailbox;
	if (mailbox != NULL && strcmp(mailbox_get_name(mailbox), name) == 0) {
		/* deleting selected mailbox. close it first */
		client_search_updates_free(client);
		storage = mailbox_get_storage(mailbox);
		client->mailbox = NULL;

		if (mailbox_close(&mailbox) < 0)
			client_send_untagged_storage_error(client, storage);
	} else {
		storage = client_find_storage(cmd, &name);
		if (storage == NULL)
			return TRUE;
	}

	if ((client_workarounds & WORKAROUND_TB_EXTRA_MAILBOX_SEP) != 0 &&
	    *name != '\0' &&
	    name[strlen(name)-1] == mail_storage_get_hierarchy_sep(storage)) {
		/* drop the extra trailing hierarchy separator */
		name = t_strndup(name, strlen(name)-1);
	}

	list = mail_storage_get_list(storage);
	if (mailbox_list_delete_mailbox(list, name) < 0)
		client_send_list_error(cmd, list);
	else {
		client_send_tagline(cmd, "OK Delete completed.");
	}
	return TRUE;
}
