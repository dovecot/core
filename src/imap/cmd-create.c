/* Copyright (c) 2002-2010 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "imap-resp-code.h"
#include "mail-namespace.h"
#include "imap-commands.h"

bool cmd_create(struct client_command_context *cmd)
{
	struct mail_namespace *ns;
	const char *mailbox, *storage_name;
	struct mailbox *box;
	bool directory;
	size_t len;

	/* <mailbox> */
	if (!client_read_string_args(cmd, 1, &mailbox))
		return FALSE;

	ns = client_find_namespace(cmd, mailbox, &storage_name);
	if (ns == NULL)
		return TRUE;

	len = strlen(mailbox);
	if (len == 0 || mailbox[len-1] != ns->sep)
		directory = FALSE;
	else if (*storage_name == '\0') {
		client_send_tagline(cmd, "NO ["IMAP_RESP_CODE_ALREADYEXISTS
				    "] Namespace already exists.");
		return TRUE;
	} else {
		/* name ends with hierarchy separator - client is just
		   informing us that it wants to create children under this
		   mailbox. */
                directory = TRUE;
		mailbox = t_strndup(mailbox, len-1);

		/* drop also from storage_name. it's already dropped when
		   WORKAROUND_TB_EXTRA_MAILBOX_SEP is enabled */
		len = strlen(storage_name);
		if (storage_name[len-1] == ns->real_sep)
			storage_name = t_strndup(storage_name, len-1);
	}

	ns = client_find_namespace(cmd, mailbox, &storage_name);
	if (ns == NULL)
		return TRUE;

	box = mailbox_alloc(ns->list, storage_name, 0);
	if (mailbox_create(box, NULL, directory) < 0)
		client_send_storage_error(cmd, mailbox_get_storage(box));
	else
		client_send_tagline(cmd, "OK Create completed.");
	mailbox_free(&box);
	return TRUE;
}
