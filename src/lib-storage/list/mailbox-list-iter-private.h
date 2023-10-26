#ifndef MAILBOX_LIST_ITER_PRIVATE_H
#define MAILBOX_LIST_ITER_PRIVATE_H

#include "mailbox-list-private.h"
#include "mailbox-list-iter.h"
#include "mailbox-list-delete.h"

struct autocreate_box {
	const char *name;
	const struct mailbox_settings *set;
	enum mailbox_info_flags flags;
	bool child_listed;
};

ARRAY_DEFINE_TYPE(mailbox_settings, const struct mailbox_settings *);
struct mailbox_list_autocreate_iterate_context {
	unsigned int idx;
	struct mailbox_info new_info;
	/* Autocreated mailboxes that match the filters */
	ARRAY(struct autocreate_box) boxes;
	/* References to settings in the boxes array. This is just for
	   convenience. */
	ARRAY_TYPE(mailbox_settings) box_sets;
	/* References to all mailbox { ... } settings in the namespace. */
	ARRAY_TYPE(mailbox_settings) all_ns_box_sets;
	HASH_TABLE(char *, char *) duplicate_vnames;
	bool listing_autoboxes:1;
};

static inline bool
mailbox_list_iter_try_delete_noselect(struct mailbox_list_iterate_context *ctx,
				      const struct mailbox_info *info,
				      const char *storage_name)
{
	if ((info->flags & (MAILBOX_NOSELECT|MAILBOX_NOCHILDREN)) ==
	    (MAILBOX_NOSELECT|MAILBOX_NOCHILDREN) &&
	    ctx->list->mail_set->mailbox_list_drop_noselect) {
		/* Try to rmdir() all \NoSelect mailbox leafs and
		   afterwards their parents. */
		mailbox_list_delete_mailbox_until_root(ctx->list, storage_name);
		return TRUE;
	}
	return FALSE;
}

#endif
