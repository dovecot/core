/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "imap-resp-code.h"
#include "mail-namespace.h"
#include "imap-commands.h"
#include "str.h"

bool cmd_create(struct client_command_context *cmd)
{
	struct mail_namespace *ns;
	const char *mailbox, *orig_mailbox;
	struct mailbox *box;
	struct mailbox_metadata metadata;
	bool directory;
	size_t len;
	string_t *msg;

	/* <mailbox> */
	if (!client_read_string_args(cmd, 1, &mailbox))
		return FALSE;

	orig_mailbox = mailbox;
	ns = client_find_namespace(cmd, &mailbox);
	if (ns == NULL)
		return TRUE;

	len = strlen(orig_mailbox);
	if (len == 0 || orig_mailbox[len-1] != mail_namespace_get_sep(ns))
		directory = FALSE;
	else {
		/* name ends with hierarchy separator - client is just
		   informing us that it wants to create children under this
		   mailbox. */
                directory = TRUE;

		/* drop separator from mailbox. it's already dropped when
		   WORKAROUND_TB_EXTRA_MAILBOX_SEP is enabled */
		if (len == strlen(mailbox))
			mailbox = t_strndup(mailbox, len-1);
	}

	box = mailbox_alloc(ns->list, mailbox, 0);
	event_add_str(cmd->event, "mailbox", mailbox_get_vname(box));
	mailbox_set_reason(box, "CREATE");
	if (mailbox_create(box, NULL, directory) < 0)
		client_send_box_error(cmd, box);
	else {
		msg = t_str_new(128);
		mailbox_get_metadata(box, MAILBOX_METADATA_GUID, &metadata);
		str_printfa(msg, "OK [MAILBOXID (%s)] Create completed.",
						 guid_128_to_string(metadata.guid));
		client_send_tagline(cmd, str_c(msg));
	}
	mailbox_free(&box);
	return TRUE;
}
