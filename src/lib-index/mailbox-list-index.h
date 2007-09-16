#ifndef MAILBOX_LIST_INDEX_H
#define MAILBOX_LIST_INDEX_H

struct mailbox_list_index_view;
struct mailbox_list_index_sync_ctx;

/* Mailbox list index contains UID <-> mailbox name mapping. It also takes in
   a mail_index index which contains UID -> metadata information for the
   mailboxes. The mmap, in-memory and lock settings are taken from the
   mail_index. */

enum mailbox_list_index_flags {
	/* Mailbox has children. They may not be indexed however, so
	   mailbox_list_index_info.has_children=FALSE is possible. */
	MAILBOX_LIST_INDEX_FLAG_CHILDREN	= 0x01,
	/* Mailbox has no children. mailbox_list_index_info.has_children
	   should be FALSE. */
	MAILBOX_LIST_INDEX_FLAG_NOCHILDREN	= 0x02,
	/* The mailbox isn't selectable (eg. a directory) */
	MAILBOX_LIST_INDEX_FLAG_NOSELECT	= 0x04,
	/* The mailbox doesn't exist at all. This is only a placeholder for
	   a child mailbox. When the children are deleted, this mailbox will
	   be automatically deleted as well. */
	MAILBOX_LIST_INDEX_FLAG_NONEXISTENT	= 0x08
};


enum mailbox_list_sync_flags {
	/* All the child mailboxes are also being synced */
	MAILBOX_LIST_SYNC_FLAG_RECURSIVE	= 0x01,
	/* New mailboxes may be added, but none are removed */
	MAILBOX_LIST_SYNC_FLAG_PARTIAL		= 0x02
};

struct mailbox_list_index_info {
	const char *name;
	uint32_t uid;
	bool has_children;
};

struct mailbox_list_index *
mailbox_list_index_alloc(const char *path, char separator,
			 struct mail_index *mail_index);
void mailbox_list_index_free(struct mailbox_list_index **index);

/* Open or create mailbox list index. */
int mailbox_list_index_open_or_create(struct mailbox_list_index *index);

/* Synchronize the index with the backend. */
int mailbox_list_index_sync_init(struct mailbox_list_index *index,
				 const char *path,
				 enum mailbox_list_sync_flags flags,
				 struct mailbox_list_index_sync_ctx **ctx_r);
struct mail_index_view *
mailbox_list_index_sync_get_view(struct mailbox_list_index_sync_ctx *ctx);
struct mail_index_transaction *
mailbox_list_index_sync_get_transaction(struct mailbox_list_index_sync_ctx*ctx);
int mailbox_list_index_sync_more(struct mailbox_list_index_sync_ctx *ctx,
				 const char *name, uint32_t *seq_r);
int mailbox_list_index_sync_commit(struct mailbox_list_index_sync_ctx **ctx);
void mailbox_list_index_sync_rollback(struct mailbox_list_index_sync_ctx **ctx);

/* Mailbox list index and mail index must be kept in sync, so lookups and
   iterations must know the mail index view. The mail_view can be set to NULL
   to use the latest changes. Returns -1 if uidvalidity doesn't match. */
int mailbox_list_index_view_init(struct mailbox_list_index *index,
				 struct mail_index_view *mail_view,
				 struct mailbox_list_index_view **view_r);
void mailbox_list_index_view_deinit(struct mailbox_list_index_view **view);

/* Get mailbox UID for a given name. Returns 1 if found, 0 if not,
   -1 if error */
int mailbox_list_index_lookup(struct mailbox_list_index_view *view,
			      const char *name, uint32_t *uid_r);

/* Iterate through all the mailboxes. If recurse_level is -1, all the child
   mailboxes are returned, otherwise it's the number of levels to return
   (0 = only the mailboxes directly under the path). Returned mailbox names
   are allocated from name_pool. */
struct mailbox_list_iter_ctx *
mailbox_list_index_iterate_init(struct mailbox_list_index_view *view,
				const char *path, int recurse_level);
/* Returns 1 if mailbox was returned, 0 at the end of iteration, -1 if error */
int mailbox_list_index_iterate_next(struct mailbox_list_iter_ctx *ctx,
				    struct mailbox_list_index_info *info_r);
void mailbox_list_index_iterate_deinit(struct mailbox_list_iter_ctx **ctx);

#endif
