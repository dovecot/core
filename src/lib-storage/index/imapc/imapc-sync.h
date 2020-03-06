#ifndef IMAPC_SYNC_H
#define IMAPC_SYNC_H

struct mailbox;
struct mailbox_sync_status;

struct imapc_sync_store {
	enum modify_type modify_type;
	const char *flags;

	ARRAY_TYPE(seq_range) uids;
};

struct imapc_sync_context {
	struct imapc_mailbox *mbox;
        struct mail_index_sync_ctx *index_sync_ctx;
	struct mail_index_view *sync_view;
	struct mail_index_transaction *trans;

	const ARRAY_TYPE(keywords) *keywords;
	ARRAY_TYPE(seq_range) expunged_uids;
	unsigned int sync_command_count;

	pool_t pool;
	HASH_TABLE(struct imapc_sync_store *, struct imapc_sync_store *) stores;

	uint32_t prev_uid1, prev_uid2;
	enum modify_type prev_modify_type;
	string_t *prev_flags;

	bool failed:1;
};

struct mailbox_sync_context *
imapc_mailbox_sync_init(struct mailbox *box, enum mailbox_sync_flags flags);
int imapc_mailbox_sync_deinit(struct mailbox_sync_context *ctx,
			      struct mailbox_sync_status *status_r);

#endif
