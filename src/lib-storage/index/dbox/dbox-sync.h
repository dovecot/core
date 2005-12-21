#ifndef __DBOX_SYNC_H
#define __DBOX_SYNC_H

#include "mail-index.h"
#include "mail-storage.h"

struct mailbox;
struct dbox_mailbox;

struct dbox_sync_rec {
	uint32_t seq1, seq2;
	enum mail_index_sync_type type;

	union {
		/* MAIL_INDEX_SYNC_TYPE_FLAGS: */
		struct {
			uint8_t add;
			uint8_t remove;
		} flags;

		/* MAIL_INDEX_SYNC_TYPE_KEYWORD_*: */
		unsigned int keyword_idx;
	} value;
};

struct dbox_sync_file_entry {
	uint32_t file_seq;

	array_t ARRAY_DEFINE(sync_recs, struct dbox_sync_rec);
};

struct dbox_sync_context {
	struct dbox_mailbox *mbox;
	struct dbox_uidlist_sync_ctx *uidlist_sync_ctx;
        struct mail_index_sync_ctx *index_sync_ctx;
	struct mail_index_view *sync_view;
	struct mail_index_transaction *trans;

	pool_t pool;
	struct hash_table *syncs; /* struct dbox_sync_file_entry */
	uint32_t prev_file_seq;

	uint32_t dotlock_failed_file_seq;

	/* full sync: */
	uint32_t mail_index_next_uid;
	array_t ARRAY_DEFINE(exists, struct seq_range);
};

int dbox_sync(struct dbox_mailbox *mbox, int force);
int dbox_sync_if_changed(struct dbox_mailbox *mbox);

struct mailbox_sync_context *
dbox_storage_sync_init(struct mailbox *box, enum mailbox_sync_flags flags);

int dbox_sync_get_file_offset(struct dbox_sync_context *ctx, uint32_t seq,
			      uint32_t *file_seq_r, uoff_t *offset_r);

int dbox_sync_update_flags(struct dbox_sync_context *ctx,
			   const struct dbox_sync_rec *sync_rec);
int dbox_sync_expunge(struct dbox_sync_context *ctx,
		      const struct dbox_sync_file_entry *entry,
                      unsigned int sync_idx);
int dbox_sync_full(struct dbox_sync_context *ctx);

#endif
