#ifndef MDBOX_SYNC_H
#define MDBOX_SYNC_H

struct mailbox;
struct mdbox_mailbox;

enum mdbox_sync_flags {
	MDBOX_SYNC_FLAG_FORCE		= 0x01,
	MDBOX_SYNC_FLAG_FSYNC		= 0x02,
	MDBOX_SYNC_FLAG_FORCE_REBUILD	= 0x04,
	MDBOX_SYNC_FLAG_NO_PURGE	= 0x08
};

struct mdbox_sync_context {
	struct mdbox_mailbox *mbox;
        struct mail_index_sync_ctx *index_sync_ctx;
	struct mail_index_view *sync_view;
	struct mail_index_transaction *trans;
	struct mdbox_map_transaction_context *map_trans;
	struct mdbox_map_atomic_context *atomic;
	enum mdbox_sync_flags flags;

	ARRAY_TYPE(seq_range) expunged_seqs;
};

int mdbox_sync_begin(struct mdbox_mailbox *mbox, enum mdbox_sync_flags flags,
		     struct mdbox_map_atomic_context *atomic,
		     struct mdbox_sync_context **ctx_r);
int mdbox_sync_finish(struct mdbox_sync_context **ctx, bool success);
int mdbox_sync(struct mdbox_mailbox *mbox, enum mdbox_sync_flags flags);

struct mailbox_sync_context *
mdbox_storage_sync_init(struct mailbox *box, enum mailbox_sync_flags flags);

#endif
