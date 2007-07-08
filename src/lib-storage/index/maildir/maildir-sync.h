#ifndef __MAILDIR_SYNC_H
#define __MAILDIR_SYNC_H

#define MAILDIR_SYNC_SECS 1

struct maildir_mailbox;

struct maildir_keywords_sync_ctx;
struct maildir_index_sync_context;

int maildir_sync_is_synced(struct maildir_mailbox *mbox);

struct mailbox_sync_context *
maildir_storage_sync_init(struct mailbox *box, enum mailbox_sync_flags flags);
int maildir_storage_sync_force(struct maildir_mailbox *mbox);

int maildir_sync_index_begin(struct maildir_mailbox *mbox,
			     struct maildir_index_sync_context **ctx_r);
int maildir_sync_index(struct maildir_index_sync_context *sync_ctx,
		       bool partial);
int maildir_sync_index_finish(struct maildir_index_sync_context **sync_ctx,
			      bool failed, bool cancel);

int maildir_sync_last_commit(struct maildir_mailbox *mbox);

struct maildir_keywords_sync_ctx *
maildir_sync_get_keywords_sync_ctx(struct maildir_index_sync_context *ctx);

#endif
