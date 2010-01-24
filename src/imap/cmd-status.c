/* Copyright (c) 2002-2010 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "imap-resp-code.h"
#include "imap-commands.h"
#include "imap-sync.h"
#include "imap-status.h"

bool cmd_status(struct client_command_context *cmd)
{
	struct client *client = cmd->client;
	const struct imap_arg *args;
	struct mailbox_status status;
	enum mailbox_status_items items;
	struct mail_namespace *ns;
	const char *mailbox, *real_mailbox, *error;
	bool selected_mailbox;

	/* <mailbox> <status items> */
	if (!client_read_args(cmd, 2, 0, &args))
		return FALSE;

	mailbox = real_mailbox = imap_arg_string(&args[0]);
	if (mailbox == NULL || args[1].type != IMAP_ARG_LIST) {
		client_send_command_error(cmd, "Status items must be list.");
		return TRUE;
	}

	/* get the items client wants */
	if (imap_status_parse_items(cmd, IMAP_ARG_LIST_ARGS(&args[1]),
				    &items) < 0)
		return TRUE;

	ns = client_find_namespace(cmd, &real_mailbox,
				   CLIENT_VERIFY_MAILBOX_SHOULD_EXIST);
	if (ns == NULL)
		return TRUE;

	selected_mailbox = client->mailbox != NULL &&
		mailbox_equals(client->mailbox, ns, real_mailbox);
	if (imap_status_get(cmd, ns, real_mailbox, items,
			    &status, &error) < 0) {
		client_send_tagline(cmd, error);
		return TRUE;
	}

	imap_status_send(client, mailbox, items, &status);
	if (!selected_mailbox)
		client_send_tagline(cmd, "OK Status completed.");
	else {
		client_send_tagline(cmd, "OK ["IMAP_RESP_CODE_CLIENTBUG"] "
				    "Status on selected mailbox completed.");
	}
	return TRUE;
}
