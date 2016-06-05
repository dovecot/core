#ifndef IMAPC_LIST_H
#define IMAPC_LIST_H

struct imap_arg;

#include "mailbox-list-private.h"

#define MAILBOX_LIST_NAME_IMAPC "imapc"

struct imapc_mailbox_list {
	struct mailbox_list list;
	const struct imapc_settings *set;
	struct imapc_storage_client *client;
	struct mailbox_list *index_list;

	/* mailboxes are stored as vnames */
	struct mailbox_tree_context *mailboxes, *tmp_subscriptions;
	char root_sep;
	time_t last_refreshed_mailboxes;

	unsigned int iter_count;

	/* mailboxes/subscriptions are fully refreshed only during
	   mailbox list iteration. */
	bool refreshed_subscriptions:1;
	bool refreshed_mailboxes:1;
	/* mailbox list's "recently refreshed" state is reset by syncing a
	   mailbox. mainly we use this to cache mailboxes' existence to avoid
	   issuing a LIST command every time. */
	bool refreshed_mailboxes_recently:1;
	bool index_list_failed:1;
	bool root_sep_pending:1;
	bool root_sep_lookup_failed:1;
};

int imapc_list_get_mailbox_flags(struct mailbox_list *list, const char *name,
				 enum mailbox_info_flags *flags_r);
int imapc_list_try_get_root_sep(struct imapc_mailbox_list *list, char *sep_r);
const char *imapc_list_to_remote(struct imapc_mailbox_list *list, const char *name);

#endif
