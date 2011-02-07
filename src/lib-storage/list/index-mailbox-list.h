#ifndef INDEX_MAILBOX_LIST_H
#define INDEX_MAILBOX_LIST_H

#include "module-context.h"
#include "mailbox-list-private.h"

#define MAILBOX_LIST_INDEX_PREFIX "dovecot.list.index"

#define INDEX_LIST_CONTEXT(obj) \
	MODULE_CONTEXT(obj, index_mailbox_list_module)

/* stored in mail_index_record.flags: */
enum mailbox_list_index_flags {
	MAILBOX_LIST_INDEX_FLAG_NONEXISTENT = MAIL_DELETED,
	MAILBOX_LIST_INDEX_FLAG_NOSELECT = MAIL_DRAFT,
	MAILBOX_LIST_INDEX_FLAG_NOINFERIORS = MAIL_ANSWERED,

	/* set during syncing for mailboxes that still exist */
	MAILBOX_LIST_INDEX_FLAG_MARKED
};

struct mailbox_list_index_record {
	/* points to given id in header */
	uint32_t name_id;
	/* parent mailbox's UID, 0 = root */
	uint32_t parent_uid;

	/* the following fields are temporarily zero while unknown,
	   also permanently zero for \NoSelect and \Nonexistent mailboxes: */

	uint8_t guid[MAIL_GUID_128_SIZE];
	uint32_t uid_validity;
};

struct mailbox_list_index_msgs_record {
	uint32_t messages;
	uint32_t unseen;
	uint32_t recent;
	uint32_t uidnext;
};

struct index_mailbox_node {
	struct index_mailbox_node *parent;
	struct index_mailbox_node *next;
	struct index_mailbox_node *children;

	uint32_t name_id, uid;
	enum mailbox_list_index_flags flags;
	const char *name;
};

struct index_mailbox_list {
	union mailbox_list_module_context module_ctx;

	const char *path;
	struct mail_index *index;
	uint32_t ext_id, msgs_ext_id, hmodseq_ext_id;

	/* Number of iterations going on. Don't refresh mailbox list while
	   any iterations are going on. */
	int iter_refcount;

	pool_t mailbox_pool;
	/* uint32_t id => const char *name */
	struct hash_table *mailbox_names;
	uint32_t highest_name_id;

	uint32_t sync_log_file_seq;
	uoff_t sync_log_file_offset;

	/* uint32_t uid => struct index_mailbox_node* */
	struct hash_table *mailbox_hash;
	struct index_mailbox_node *mailbox_tree;

	unsigned int force_refresh:1;
};

struct index_mailbox_list_iterate_context {
	struct mailbox_list_iterate_context ctx;
	struct mailbox_list_iterate_context *backend_ctx;

	struct mailbox_info info;
	unsigned int parent_len;
	string_t *path;
	struct index_mailbox_node *next_node;
	char sep;

	unsigned int failed:1;
};

extern MODULE_CONTEXT_DEFINE(index_mailbox_list_module,
			     &mailbox_list_module_register);

struct index_mailbox_node *
index_mailbox_list_lookup(struct mailbox_list *list, const char *vname);

int index_mailbox_list_refresh(struct mailbox_list *list);

void index_mailbox_list_status_init(void);
void index_mailbox_list_status_init_list(struct mailbox_list *list);

#endif
