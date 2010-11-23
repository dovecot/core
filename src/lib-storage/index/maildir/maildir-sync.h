#ifndef MAILDIR_SYNC_H
#define MAILDIR_SYNC_H

/* All systems accessing the filesystem must have their clock less than this
   many seconds apart from each others. 0 works only for local filesystems. */
#define MAILDIR_SYNC_SECS 1

/* After moving this many mails from new/ to cur/, check if we need to touch
   the uidlist lock. */
#define MAILDIR_SLOW_MOVE_COUNT 100
/* readdir() should be pretty fast to do, but check anyway every n files
   to see if we need to touch the uidlist lock. */
#define MAILDIR_SLOW_CHECK_COUNT 10000
/* If syncing takes longer than this, log a warning. */
#define MAILDIR_SYNC_TIME_WARN_SECS 60

struct maildir_mailbox;

struct maildir_sync_context;
struct maildir_keywords_sync_ctx;
struct maildir_index_sync_context;

int maildir_sync_is_synced(struct maildir_mailbox *mbox);

struct mailbox_sync_context *
maildir_storage_sync_init(struct mailbox *box, enum mailbox_sync_flags flags);
int maildir_storage_sync_force(struct maildir_mailbox *mbox, uint32_t uid);

int maildir_sync_header_refresh(struct maildir_mailbox *mbox);

int maildir_sync_index_begin(struct maildir_mailbox *mbox,
			     struct maildir_sync_context *maildir_sync_ctx,
			     struct maildir_index_sync_context **ctx_r);
int maildir_sync_index(struct maildir_index_sync_context *sync_ctx,
		       bool partial);
int maildir_sync_index_commit(struct maildir_index_sync_context **_ctx);
void maildir_sync_index_rollback(struct maildir_index_sync_context **_ctx);

struct maildir_keywords_sync_ctx *
maildir_sync_get_keywords_sync_ctx(struct maildir_index_sync_context *ctx);
void maildir_sync_notify(struct maildir_sync_context *ctx);
void maildir_sync_set_new_msgs_count(struct maildir_index_sync_context *ctx,
				     unsigned int count);

int maildir_list_index_has_changed(struct mailbox *box,
				   struct mail_index_view *list_view,
				   uint32_t seq);
int maildir_list_index_update_sync(struct mailbox *box,
				   struct mail_index_transaction *trans,
				   uint32_t seq);

#endif
