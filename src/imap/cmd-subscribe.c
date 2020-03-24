/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "imap-utf7.h"
#include "imap-commands.h"
#include "mail-namespace.h"

static bool
subscribe_is_valid_name(struct client_command_context *cmd, struct mailbox *box)
{
	enum mailbox_existence existence;

	if (mailbox_exists(box, TRUE, &existence) < 0) {
		client_send_box_error(cmd, box);
		return FALSE;
	}
	if (existence == MAILBOX_EXISTENCE_NONE) {
		client_send_tagline(cmd, t_strdup_printf(
			"NO "MAIL_ERRSTR_MAILBOX_NOT_FOUND,
			mailbox_get_vname(box)));
		return FALSE;
	}
	return TRUE;
}

static bool str_ends_with_char(const char *str, char c)
{
	size_t len = strlen(str);

	return len > 0 && str[len-1] == c;
}

bool cmd_subscribe_full(struct client_command_context *cmd, bool subscribe)
{
	struct mail_namespace *ns;
	struct mailbox *box, *box2;
	const char *mailbox, *orig_mailbox;
	bool unsubscribed_mailbox2;
	char sep;

	/* <mailbox> */
	if (!client_read_string_args(cmd, 1, &mailbox))
		return FALSE;
	orig_mailbox = mailbox;

	ns = client_find_namespace(cmd, &mailbox);
	if (ns == NULL)
		return TRUE;

	box = mailbox_alloc(ns->list, mailbox, 0);
	event_add_str(cmd->event, "mailbox", mailbox_get_vname(box));
	mailbox_set_reason(box, subscribe ? "SUBSCRIBE" : "UNSUBSCRIBE");
	if (subscribe) {
		if (!subscribe_is_valid_name(cmd, box)) {
			mailbox_free(&box);
			return TRUE;
		}
	}

	sep = mail_namespace_get_sep(ns);
	unsubscribed_mailbox2 = FALSE;
	if (!subscribe &&
	    str_ends_with_char(orig_mailbox, sep) &&
	    !str_ends_with_char(mailbox, sep)) {
		/* try to unsubscribe both "box" and "box/" */
		const char *name2 = t_strdup_printf("%s%c", mailbox, sep);
		box2 = mailbox_alloc(ns->list, name2, 0);
		mailbox_set_reason(box2, "UNSUBSCRIBE");
		if (mailbox_set_subscribed(box2, FALSE) == 0)
			unsubscribed_mailbox2 = TRUE;
		mailbox_free(&box2);
	}

	if (mailbox_set_subscribed(box, subscribe) < 0 &&
	    !unsubscribed_mailbox2) {
		client_send_box_error(cmd, box);
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
