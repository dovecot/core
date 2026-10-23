#ifndef INDEX_MAILBOX_SIZE_H
#define INDEX_MAILBOX_SIZE_H

struct mailbox;
struct mailbox_transaction_context;
struct mail_index_sync_ctx;
struct mail_index_view;

struct mailbox_vsize_update *
index_mailbox_vsize_update_init(struct mailbox *box);
void index_mailbox_vsize_update_deinit(struct mailbox_vsize_update **update);

void index_mailbox_vsize_hdr_expunge(struct mailbox_vsize_update *update,
				     uint32_t uid, uoff_t vsize);

bool index_mailbox_vsize_update_try_lock(struct mailbox_vsize_update *update);
bool index_mailbox_vsize_update_wait_lock(struct mailbox_vsize_update *update);
/* Returns TRUE if expunges & appends should be updating the header. */
bool index_mailbox_vsize_want_updates(struct mailbox_vsize_update *update);

void index_mailbox_vsize_update_appends(struct mailbox *box);
/* Add saved mails to the vsize header within the transaction. Call after
   the UIDs are assigned, with the index still sync-locked by sync_ctx. */
void index_mailbox_vsize_hdr_add_saved(struct mailbox_transaction_context *t,
				       struct mail_index_sync_ctx *sync_ctx,
				       struct mail_index_view *sync_view);

#endif
