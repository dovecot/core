/* Copyright (c) 2002-2010 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "imap-commands.h"
#include "mail-namespace.h"

static bool
subscribe_is_valid_name(struct client_command_context *cmd, struct mailbox *box)
{
	int ret;

	if ((ret = mailbox_exists(box)) < 0) {
		client_send_storage_error(cmd, mailbox_get_storage(box));
		return FALSE;
	}
	if (ret == 0) {
		client_send_tagline(cmd, t_strdup_printf(
			"NO "MAIL_ERRSTR_MAILBOX_NOT_FOUND,
			mailbox_get_vname(box)));
		return FALSE;
	}
	return TRUE;
}

bool cmd_subscribe_full(struct client_command_context *cmd, bool subscribe)
{
	struct mail_namespace *ns;
	struct mailbox *box, *box2;
	const char *mailbox, *orig_mailbox;
	bool unsubscribed_mailbox2;

	/* <mailbox> */
	if (!client_read_string_args(cmd, 1, &mailbox))
		return FALSE;
	orig_mailbox = mailbox;

	ns = client_find_namespace(cmd, &mailbox);
	if (ns == NULL)
		return TRUE;

	box = mailbox_alloc(ns->list, mailbox, 0);
	if (subscribe) {
		if (!subscribe_is_valid_name(cmd, box)) {
			mailbox_free(&box);
			return TRUE;
		}
	}

	unsubscribed_mailbox2 = FALSE;
	if (!subscribe && mailbox != orig_mailbox) {
		/* try to unsubscribe both "box" and "box/" */
		box2 = mailbox_alloc(ns->list, orig_mailbox, 0);
		if (mailbox_set_subscribed(box2, FALSE) == 0)
			unsubscribed_mailbox2 = TRUE;
		mailbox_free(&box2);
	}

	if (mailbox_set_subscribed(box, subscribe) < 0 &&
	    !unsubscribed_mailbox2) {
		client_send_storage_error(cmd, mailbox_get_storage(box));
	} else {
		client_send_tagline(cmd, subscribe ?
				    "OK Subscribe completed." :
				    "OK Unsubscribe completed.");
	}
	mailbox_free(&box);
	return TRUE;
}

bool cmd_subscribe(struct client_command_context *cmd)
{
	return cmd_subscribe_full(cmd, TRUE);
}
