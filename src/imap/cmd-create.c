/* Copyright (c) 2002-2009 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "mail-namespace.h"
#include "imap-commands.h"

bool cmd_create(struct client_command_context *cmd)
{
	struct mail_namespace *ns;
	struct mail_storage *storage;
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
	else if (*mailbox == '\0') {
		client_send_tagline(cmd, "NO Namespace already exists.");
		return TRUE;
	} else {
		/* name ends with hierarchy separator - client is just
		   informing us that it wants to create children under this
		   mailbox. */
                directory = TRUE;
		mailbox = t_strndup(mailbox, strlen(mailbox)-1);
		full_mailbox = t_strndup(full_mailbox, len-1);
	}

	if (!client_verify_mailbox_name(cmd, full_mailbox,
					CLIENT_VERIFY_MAILBOX_SHOULD_NOT_EXIST))
		return TRUE;

	storage = mail_namespace_get_default_storage(ns);
	if (mail_storage_mailbox_create(storage, ns, mailbox, directory) < 0)
		client_send_storage_error(cmd, storage);
	else
		client_send_tagline(cmd, "OK Create completed.");
	return TRUE;
}
