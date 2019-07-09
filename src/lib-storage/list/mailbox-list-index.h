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
#include "mail-types.h"
#include "mail-storage.h"
#include "mailbox-list-private.h"

#include <sys/time.h>

#define MAILBOX_LIST_INDEX_HIERARCHY_SEP '~'

#define INDEX_LIST_CONTEXT(obj) \
	MODULE_CONTEXT(obj, mailbox_list_index_module)
#define INDEX_LIST_CONTEXT_REQUIRE(obj) \
	MODULE_CONTEXT_REQUIRE(obj, mailbox_list_index_module)

/* Should the STATUS information for this mailbox not be written to the
   mailbox list index? */
#define MAILBOX_IS_NEVER_IN_INDEX(box) \
	((box)->inbox_any && !(box)->storage->set->mailbox_list_index_include_inbox)

struct mail_index_view;
struct mailbox_index_vsize;
struct mailbox_vfuncs;

/* stored in mail_index_record.flags: */
enum mailbox_list_index_flags {
	MAILBOX_LIST_INDEX_FLAG_NONEXISTENT = MAIL_DELETED,
	MAILBOX_LIST_INDEX_FLAG_NOSELECT = MAIL_DRAFT,
	MAILBOX_LIST_INDEX_FLAG_NOINFERIORS = MAIL_ANSWERED,
	MAILBOX_LIST_INDEX_FLAG_CORRUPTED_NAME = MAIL_SEEN,

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
	/* extension data is corrupted on disk - need to update it */
	bool corrupted_ext;
	/* flags are corrupted on disk - need to update it */
	bool corrupted_flags;
	const char *name;
};

struct mailbox_list_index {
	union mailbox_list_module_context module_ctx;

	const char *path;
	struct mail_index *index;
	uint32_t ext_id, msgs_ext_id, hmodseq_ext_id, subs_hdr_ext_id;
	uint32_t vsize_ext_id, first_saved_ext_id;
	struct timeval last_refresh_timeval;

	pool_t mailbox_pool;
	/* uin32_t id => name */
	HASH_TABLE(void *, char *) mailbox_names;
	uint32_t highest_name_id;

	struct mailbox_list_index_sync_context *sync_ctx;
	uint32_t sync_log_file_seq;
	uoff_t sync_log_file_offset;
	uint32_t sync_stamp;
	struct timeout *to_refresh;

	/* uint32_t uid => node */
	HASH_TABLE(void *, struct mailbox_list_index_node *) mailbox_hash;
	struct mailbox_list_index_node *mailbox_tree;

	bool pending_init:1;
	bool opened:1;
	bool syncing:1;
	bool updating_status:1;
	bool has_backing_store:1;
	bool index_last_check_changed:1;
	bool corrupted_names_or_parents:1;
	bool handling_corruption:1;
	bool call_corruption_callback:1;
	bool rebuild_on_missing_inbox:1;
	bool force_resynced:1;
	bool force_resync_failed:1;
};

struct mailbox_list_index_iterate_context {
	struct mailbox_list_iterate_context ctx;
	pool_t mailbox_pool;

	struct mailbox_info info;
	pool_t info_pool;

	size_t parent_len;
	string_t *path;
	struct mailbox_list_index_node *next_node;

	bool failed:1;
	bool prefix_inbox_list:1;
};

extern MODULE_CONTEXT_DEFINE(mailbox_list_index_module,
			     &mailbox_list_module_register);

void mailbox_list_index_set_index_error(struct mailbox_list *list);
struct mailbox_list_index_node *
mailbox_list_index_lookup(struct mailbox_list *list, const char *name);
struct mailbox_list_index_node *
mailbox_list_index_lookup_uid(struct mailbox_list_index *ilist, uint32_t uid);
void mailbox_list_index_node_get_path(const struct mailbox_list_index_node *node,
				      char sep, string_t *str);
void mailbox_list_index_node_unlink(struct mailbox_list_index *ilist,
				    struct mailbox_list_index_node *node);

int mailbox_list_index_index_open(struct mailbox_list *list);
bool mailbox_list_index_need_refresh(struct mailbox_list_index *ilist,
				     struct mail_index_view *view);
/* Refresh the index, but only if it hasn't been refreshed "recently"
   (= within this same ioloop run) */
int mailbox_list_index_refresh(struct mailbox_list *list);
/* Refresh the index regardless of when the last refresh was done. */
int mailbox_list_index_refresh_force(struct mailbox_list *list);
void mailbox_list_index_refresh_later(struct mailbox_list *list);
int mailbox_list_index_handle_corruption(struct mailbox_list *list);
int mailbox_list_index_set_uncorrupted(struct mailbox_list *list);

struct mailbox_list_index_node *
mailbox_list_index_node_find_sibling(struct mailbox_list_index_node *node,
				     const char *name);
void mailbox_list_index_reset(struct mailbox_list_index *ilist);
int mailbox_list_index_parse(struct mailbox_list *list,
			     struct mail_index_view *view, bool force);

struct mailbox_list_iterate_context *
mailbox_list_index_iter_init(struct mailbox_list *list,
			     const char *const *patterns,
			     enum mailbox_list_iter_flags flags);
const struct mailbox_info *
mailbox_list_index_iter_next(struct mailbox_list_iterate_context *ctx);
int mailbox_list_index_iter_deinit(struct mailbox_list_iterate_context *ctx);

bool mailbox_list_index_status(struct mailbox_list *list,
			       struct mail_index_view *view,
			       uint32_t seq, enum mailbox_status_items items,
			       struct mailbox_status *status_r,
			       uint8_t *mailbox_guid,
			       struct mailbox_index_vsize *vsize_r);
void mailbox_list_index_status_set_info_flags(struct mailbox *box, uint32_t uid,
					      enum mailbox_info_flags *flags);
void mailbox_list_index_update_mailbox_index(struct mailbox *box,
					     const struct mailbox_update *update);

int mailbox_list_index_notify_init(struct mailbox_list *list,
				   enum mailbox_list_notify_event mask,
				   struct mailbox_list_notify **notify_r);
void mailbox_list_index_notify_deinit(struct mailbox_list_notify *notify);
int mailbox_list_index_notify_next(struct mailbox_list_notify *notify,
				   const struct mailbox_list_notify_rec **rec_r);
void mailbox_list_index_notify_wait(struct mailbox_list_notify *notify,
				    void (*callback)(void *context),
				    void *context);
void mailbox_list_index_notify_flush(struct mailbox_list_notify *notify);

void mailbox_list_index_status_init_mailbox(struct mailbox_vfuncs *v);
bool mailbox_list_index_backend_init_mailbox(struct mailbox *box,
					     struct mailbox_vfuncs *v);
void mailbox_list_index_status_init_finish(struct mailbox_list *list);

void mailbox_list_index_status_sync_init(struct mailbox *box);
void mailbox_list_index_status_sync_deinit(struct mailbox *box);

void mailbox_list_index_backend_sync_init(struct mailbox *box,
					  enum mailbox_sync_flags flags);
int mailbox_list_index_backend_sync_deinit(struct mailbox *box);

#endif
