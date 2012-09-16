#ifndef CYDIR_SYNC_H
#define CYDIR_SYNC_H

struct mailbox;
struct mailbox_sync_status;

struct imapc_sync_context {
	struct imapc_mailbox *mbox;
        struct mail_index_sync_ctx *index_sync_ctx;
	struct mail_index_view *sync_view;
	struct mail_index_transaction *trans;

	const ARRAY_TYPE(keywords) *keywords;
	ARRAY_TYPE(seq_range) expunged_uids;
	unsigned int sync_command_count;

	unsigned int failed:1;
};

struct mailbox_sync_context *
imapc_mailbox_sync_init(struct mailbox *box, enum mailbox_sync_flags flags);
int imapc_mailbox_sync_deinit(struct mailbox_sync_context *ctx,
			      struct mailbox_sync_status *status_r);
void imapc_sync_mailbox_reopened(struct imapc_mailbox *mbox);

#endif
