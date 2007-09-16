#ifndef INDEX_MAILBOX_LIST_H
#define INDEX_MAILBOX_LIST_H

#include "module-context.h"
#include "mailbox-list-private.h"

#define MAIL_INDEX_PREFIX "dovecot.list.index"
#define MAILBOX_LIST_INDEX_NAME MAIL_INDEX_PREFIX".uidmap"

#define INDEX_LIST_CONTEXT(obj) \
	MODULE_CONTEXT(obj, index_mailbox_list_module)

struct index_mailbox_list {
	union mailbox_list_module_context module_ctx;

	struct mail_index *mail_index;
	struct mailbox_list_index *list_index;
	struct mailbox_list_index_view *list_sync_view;

	uint32_t eid_messages, eid_unseen, eid_recent;
	uint32_t eid_uid_validity, eid_uidnext;
};

struct index_mailbox_list_iterate_context {
	struct mailbox_list_iterate_context ctx;

	struct mailbox_list_iter_ctx *iter_ctx;
	struct mailbox_list_iterate_context *backend_ctx;

	struct mailbox_tree_context *subs_tree;
	struct mailbox_tree_iterate_context *subs_iter;

	struct mailbox_list_index_view *view;
	struct mail_index_view *mail_view;
	struct mail_index_transaction *trans;

	char *prefix;
	int recurse_level;
	struct imap_match_glob *glob;

	const char *ns_prefix;
	unsigned int ns_prefix_len;

	pool_t info_pool;
	struct mailbox_info info;
	uint32_t sync_stamp;

	unsigned int failed:1;
};

extern MODULE_CONTEXT_DEFINE(index_mailbox_list_module,
			     &mailbox_list_module_register);

void index_mailbox_list_sync_init(void);
void index_mailbox_list_sync_init_list(struct mailbox_list *list);

#endif
