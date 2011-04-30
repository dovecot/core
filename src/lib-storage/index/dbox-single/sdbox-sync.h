#ifndef SDBOX_SYNC_H
#define SDBOX_SYNC_H

struct mailbox;
struct sdbox_mailbox;

enum sdbox_sync_flags {
	SDBOX_SYNC_FLAG_FORCE		= 0x01,
	SDBOX_SYNC_FLAG_FSYNC		= 0x02,
	SDBOX_SYNC_FLAG_FORCE_REBUILD	= 0x04
};

enum sdbox_sync_entry_type {
	SDBOX_SYNC_ENTRY_TYPE_EXPUNGE,
	SDBOX_SYNC_ENTRY_TYPE_MOVE_FROM_ALT,
	SDBOX_SYNC_ENTRY_TYPE_MOVE_TO_ALT
};

struct sdbox_sync_context {
	struct sdbox_mailbox *mbox;
        struct mail_index_sync_ctx *index_sync_ctx;
	struct mail_index_view *sync_view;
	struct mail_index_transaction *trans;
	enum sdbox_sync_flags flags;
	ARRAY_TYPE(uint32_t) expunged_uids;
};

int sdbox_sync_begin(struct sdbox_mailbox *mbox, enum sdbox_sync_flags flags,
		     struct sdbox_sync_context **ctx_r);
int sdbox_sync_finish(struct sdbox_sync_context **ctx, bool success);
int sdbox_sync(struct sdbox_mailbox *mbox, enum sdbox_sync_flags flags);

int sdbox_sync_index_rebuild(struct sdbox_mailbox *mbox, bool force);

struct mailbox_sync_context *
sdbox_storage_sync_init(struct mailbox *box, enum mailbox_sync_flags flags);

#endif
