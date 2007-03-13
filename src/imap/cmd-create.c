/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "namespace.h"
#include "commands.h"

bool cmd_create(struct client_command_context *cmd)
{
	struct namespace *ns;
	const char *mailbox, *full_mailbox;
	bool directory;
	size_t len;

	/* <mailbox> */
	if (!client_read_string_args(cmd, 1, &mailbox))
		return FALSE;
	full_mailbox = mailbox;

	ns = client_find_namespace(cmd, &mailbox);
	if (ns == NULL)
		return TRUE;

	len = strlen(full_mailbox);
	if (len == 0 || full_mailbox[len-1] != ns->sep)
		directory = FALSE;
	else {
		/* name ends with hierarchy separator - client is just
		   informing us that it wants to create children under this
		   mailbox. */
                directory = TRUE;
		mailbox = t_strndup(mailbox, len-1);
		full_mailbox = t_strndup(full_mailbox, strlen(full_mailbox)-1);
	}

	if (!client_verify_mailbox_name(cmd, full_mailbox, FALSE, TRUE))
		return TRUE;

	if (mail_storage_mailbox_create(ns->storage, mailbox, directory) < 0)
		client_send_storage_error(cmd, ns->storage);
	else
		client_send_tagline(cmd, "OK Create completed.");
	return TRUE;
}
