/* Copyright (c) 2002-2009 Dovecot authors, see the included COPYING file */

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
	struct mail_namespace *ns, *real_ns;
	const char *mailbox, *mailbox2 = NULL, *verify_name, *real_name;
	bool unsubscribed_mailbox2;

	/* <mailbox> */
	if (!client_read_string_args(cmd, 1, &mailbox))
		return FALSE;
	verify_name = mailbox;

	real_name = mailbox;
	real_ns = client_find_namespace(cmd, &real_name,
					CLIENT_VERIFY_MAILBOX_NONE);
	if (real_ns == NULL)
		return TRUE;

	/* now find a namespace where the subscription can be added to */
	ns = mail_namespace_find_subscribable(cmd->client->user->namespaces,
					      &mailbox);
	if (ns == NULL) {
		client_send_tagline(cmd, "NO Unknown subscription namespace.");
		return TRUE;
	}

	if (ns != real_ns) {
		/* subscription is being written to a different namespace
		   than where the mailbox exists. */
		mailbox = t_strconcat(real_ns->prefix, real_name, NULL);
		/* drop the common prefix */
		i_assert(strncmp(ns->prefix, mailbox, strlen(ns->prefix)) == 0);
		mailbox += strlen(ns->prefix);
	}

	if ((cmd->client->set->parsed_workarounds &
	     		WORKAROUND_TB_EXTRA_MAILBOX_SEP) != 0 &&
	    *mailbox != '\0' && mailbox[strlen(mailbox)-1] ==
	    mailbox_list_get_hierarchy_sep(ns->list)) {
		/* verify the validity without the trailing '/' */
		verify_name = t_strndup(verify_name, strlen(verify_name)-1);
		mailbox2 = mailbox;
		mailbox = t_strndup(mailbox, strlen(mailbox)-1);
	}

	if (have_listable_namespace_prefix(cmd->client->user->namespaces,
					   verify_name)) {
		/* subscribing to a listable namespace prefix, allow it. */
	} else if (subscribe) {
		if (client_find_namespace(cmd, &verify_name,
				CLIENT_VERIFY_MAILBOX_SHOULD_EXIST) == NULL)
			return TRUE;
	} else {
		if (client_find_namespace(cmd, &verify_name,
				CLIENT_VERIFY_MAILBOX_NAME) == NULL)
			return TRUE;
	}

	unsubscribed_mailbox2 = FALSE;
	if (!subscribe && mailbox2 != NULL) {
		/* try to unsubscribe both "box" and "box/" */
		if (mailbox_list_set_subscribed(ns->list, mailbox2, FALSE) == 0)
			unsubscribed_mailbox2 = TRUE;
	}

	if (mailbox_list_set_subscribed(ns->list, mailbox, subscribe) < 0 &&
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
