/* Copyright (c) 2002-2010 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "imap-resp-code.h"
#include "mail-namespace.h"
#include "imap-commands.h"

bool cmd_create(struct client_command_context *cmd)
{
	struct mail_namespace *ns;
	const char *mailbox, *full_mailbox;
	struct mailbox *box;
	bool directory;
	size_t len;

	/* <mailbox> */
	if (!client_read_string_args(cmd, 1, &mailbox))
		return FALSE;
	full_mailbox = mailbox;

	ns = client_find_namespace(cmd, &mailbox, CLIENT_VERIFY_MAILBOX_NONE);
	if (ns == NULL)
		return TRUE;

	len = strlen(full_mailbox);
	if (len == 0 || full_mailbox[len-1] != ns->sep)
		directory = FALSE;
	else if (*mailbox == '\0') {
		client_send_tagline(cmd, "NO ["IMAP_RESP_CODE_ALREADYEXISTS
				    "] Namespace already exists.");
		return TRUE;
	} else {
		/* name ends with hierarchy separator - client is just
		   informing us that it wants to create children under this
		   mailbox. */
                directory = TRUE;
		mailbox = t_strndup(mailbox, strlen(mailbox)-1);
		full_mailbox = t_strndup(full_mailbox, len-1);
	}

	mailbox = full_mailbox;
	ns = client_find_namespace(cmd, &mailbox,
				   CLIENT_VERIFY_MAILBOX_SHOULD_NOT_EXIST);
	if (ns == NULL)
		return TRUE;

	box = mailbox_alloc(ns->list, mailbox, NULL, 0);
	if (mailbox_create(box, NULL, directory) < 0)
		client_send_storage_error(cmd, mailbox_get_storage(box));
	else
		client_send_tagline(cmd, "OK Create completed.");
	mailbox_close(&box);
	return TRUE;
}
