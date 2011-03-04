/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "imap-commands.h"
#include "mail-namespace.h"

static bool have_listable_namespace_prefix(struct mail_namespace *ns,
					   const char *name)
{
	unsigned int name_len = strlen(name);

	for (; ns != NULL; ns = ns->next) {
		if ((ns->flags & (NAMESPACE_FLAG_LIST_PREFIX |
				  NAMESPACE_FLAG_LIST_CHILDREN)) == 0)
			continue;

		if (ns->prefix_len <= name_len)
			continue;

		/* if prefix has multiple hierarchies, allow subscribing to
		   any of the hierarchies */
		if (strncmp(ns->prefix, name, name_len) == 0 &&
		    ns->prefix[name_len] == ns->sep)
			return TRUE;
	}
	return FALSE;
}

bool cmd_subscribe_full(struct client_command_context *cmd, bool subscribe)
{
	enum mailbox_name_status status;
	struct mail_namespace *ns, *box_ns;
	const char *mailbox, *storage_name, *subs_name, *subs_name2 = NULL;
	bool unsubscribed_mailbox2;

	/* <mailbox> */
	if (!client_read_string_args(cmd, 1, &mailbox))
		return FALSE;

	box_ns = client_find_namespace(cmd, mailbox, &storage_name, NULL);
	if (box_ns == NULL)
		return TRUE;

	/* now find a namespace where the subscription can be added to */
	subs_name = mailbox;
	ns = mail_namespace_find_subscribable(cmd->client->user->namespaces,
					      &subs_name);
	if (ns == NULL) {
		client_send_tagline(cmd, "NO Unknown subscription namespace.");
		return TRUE;
	}

	if (ns != box_ns) {
		/* subscription is being written to a different namespace
		   than where the mailbox exists. */
		subs_name = t_strconcat(box_ns->prefix, storage_name, NULL);
		/* drop the common prefix */
		i_assert(strncmp(ns->prefix, subs_name, strlen(ns->prefix)) == 0);
		subs_name += strlen(ns->prefix);
	}

	if ((cmd->client->set->parsed_workarounds &
	     WORKAROUND_TB_EXTRA_MAILBOX_SEP) != 0 &&
	    *subs_name != '\0' &&
	    subs_name[strlen(subs_name)-1] == ns->real_sep) {
		/* verify the validity without the trailing '/' */
		mailbox = t_strndup(mailbox, strlen(mailbox)-1);
		subs_name2 = subs_name;
		subs_name = t_strndup(subs_name, strlen(subs_name)-1);
	}

	if (have_listable_namespace_prefix(cmd->client->user->namespaces,
					   mailbox)) {
		/* subscribing to a listable namespace prefix, allow it. */
	} else if (subscribe) {
		if (client_find_namespace(cmd, mailbox,
					  &storage_name, &status) == NULL)
			return TRUE;
		switch (status) {
		case MAILBOX_NAME_EXISTS_MAILBOX:
		case MAILBOX_NAME_EXISTS_DIR:
			break;
		case MAILBOX_NAME_VALID:
		case MAILBOX_NAME_INVALID:
		case MAILBOX_NAME_NOINFERIORS:
			client_fail_mailbox_name_status(cmd, mailbox,
							NULL, status);
			return TRUE;
		}
	} else {
		if (client_find_namespace(cmd, mailbox,
					  &storage_name, &status) == NULL)
			return TRUE;
		switch (status) {
		case MAILBOX_NAME_EXISTS_MAILBOX:
		case MAILBOX_NAME_EXISTS_DIR:
		case MAILBOX_NAME_VALID:
			break;
		case MAILBOX_NAME_INVALID:
		case MAILBOX_NAME_NOINFERIORS:
			client_fail_mailbox_name_status(cmd, mailbox,
							NULL, status);
			return TRUE;
		}
	}

	unsubscribed_mailbox2 = FALSE;
	if (!subscribe && subs_name2 != NULL) {
		/* try to unsubscribe both "box" and "box/" */
		if (mailbox_list_set_subscribed(ns->list, subs_name2,
						FALSE) == 0)
			unsubscribed_mailbox2 = TRUE;
	}

	if (mailbox_list_set_subscribed(ns->list, subs_name, subscribe) < 0 &&
	    !unsubscribed_mailbox2) {
		client_send_list_error(cmd, ns->list);
	} else {
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
