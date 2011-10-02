#ifndef MAILBOX_LIST_INDEX_H
#define MAILBOX_LIST_INDEX_H

/* Mailbox list index basically contains:

   Header contains ID => name mapping. The name isn't the full mailbox name,
   but rather each hierarchy level has its own ID and name. For example a
   mailbox name "foo/bar" (with '/' as separator) would have separate IDs for
   "foo" and "bar" names.

   The records contain { parent_uid, uid, name_id } field that can be used to
   build the whole mailbox tree. parent_uid=0 means root, otherwise it's the
   parent node's uid.

   Each record also contains GUID for each selectable mailbox. If a mailbox
   is recreated using the same name, its GUID also changes. Note however that
   the UID doesn't change, because the UID refers to the mailbox name, not to
   the mailbox itself.

   The records may contain also extensions for allowing mailbox_get_status()
   to return values directly from the mailbox list index. Storage backends
   may also add their own extensions to figure out if a record is up to date.
*/

#include "module-context.h"
#include "mailbox-list-private.h"

#define MAILBOX_LIST_INDEX_PREFIX "dovecot.list.index"

#define INDEX_LIST_CONTEXT(obj) \
	MODULE_CONTEXT(obj, mailbox_list_index_module)

struct mail_index_view;
struct mailbox;

/* stored in mail_index_record.flags: */
enum mailbox_list_index_flags {
	MAILBOX_LIST_INDEX_FLAG_NONEXISTENT = MAIL_DELETED,
	MAILBOX_LIST_INDEX_FLAG_NOSELECT = MAIL_DRAFT,
	MAILBOX_LIST_INDEX_FLAG_NOINFERIORS = MAIL_ANSWERED,

	/* set during syncing for mailboxes that still exist */
	MAILBOX_LIST_INDEX_FLAG_SYNC_EXISTS = MAIL_FLAGGED
};

struct mailbox_list_index_header {
	uint8_t refresh_flag;
	/* array of { uint32_t id; char name[]; } */
};

struct mailbox_list_index_record {
	/* points to given id in header */
	uint32_t name_id;
	/* parent mailbox's UID, 0 = root */
	uint32_t parent_uid;

	/* the following fields are temporarily zero while unknown,
	   also permanently zero for \NoSelect and \Nonexistent mailboxes: */

	guid_128_t guid;
	uint32_t uid_validity;
};

struct mailbox_list_index_msgs_record {
	uint32_t messages;
	uint32_t unseen;
	uint32_t recent;
	uint32_t uidnext;
};

struct mailbox_list_index_node {
	struct mailbox_list_index_node *parent;
	struct mailbox_list_index_node *next;
	struct mailbox_list_index_node *children;

	uint32_t name_id, uid;
	enum mailbox_list_index_flags flags;
	const char *name;
};

struct mailbox_list_index {
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

	uint32_t sync_stamp;

	/* uint32_t uid => struct mailbox_list_index_node* */
	struct hash_table *mailbox_hash;
	struct mailbox_list_index_node *mailbox_tree;
};

struct mailbox_list_index_iterate_context {
	struct mailbox_list_iterate_context ctx;
	struct mailbox_list_iterate_context *backend_ctx;

	struct mailbox_info info;
	unsigned int parent_len;
	string_t *path;
	struct mailbox_list_index_node *next_node;
	char sep;

	unsigned int failed:1;
};

extern MODULE_CONTEXT_DEFINE(mailbox_list_index_module,
			     &mailbox_list_module_register);

void mailbox_list_index_set_index_error(struct mailbox_list *list);
struct mailbox_list_index_node *
mailbox_list_index_lookup(struct mailbox_list *list, const char *name);

int mailbox_list_index_refresh(struct mailbox_list *list);
void mailbox_list_index_refresh_later(struct mailbox_list *list);

struct mailbox_list_index_node *
mailbox_list_index_node_find_sibling(struct mailbox_list_index_node *node,
				     const char *name);
void mailbox_list_index_reset(struct mailbox_list_index *ilist);
int mailbox_list_index_parse(struct mailbox_list_index *ilist,
			     struct mail_index_view *view, bool force);
int mailbox_list_index_sync(struct mailbox_list *list);

struct mailbox_list_iterate_context *
mailbox_list_index_iter_init(struct mailbox_list *list,
			     const char *const *patterns,
			     enum mailbox_list_iter_flags flags);
const struct mailbox_info *
mailbox_list_index_iter_next(struct mailbox_list_iterate_context *ctx);
int mailbox_list_index_iter_deinit(struct mailbox_list_iterate_context *ctx);

void mailbox_list_index_status_set_info_flags(struct mailbox *box, uint32_t uid,
					      enum mailbox_info_flags *flags);

void mailbox_list_index_status_init(void);
void mailbox_list_index_status_init_list(struct mailbox_list *list);

#endif
