#ifndef DBOX_SYNC_H
#define DBOX_SYNC_H

struct mailbox;

struct dbox_sync_file_entry {
	uint32_t uid, file_id;

	unsigned int move_from_alt:1;
	unsigned int move_to_alt:1;
	ARRAY_TYPE(seq_range) expunges;
};

struct dbox_sync_context {
	struct dbox_mailbox *mbox;
        struct mail_index_sync_ctx *index_sync_ctx;
	struct mail_index_view *sync_view;
	struct mail_index_transaction *trans;

	string_t *path;
	unsigned int path_dir_prefix_len;

	pool_t pool;
	struct hash_table *syncs; /* struct dbox_sync_file_entry */
};

int dbox_sync_begin(struct dbox_mailbox *mbox, bool force,
		    struct dbox_sync_context **ctx_r);
int dbox_sync_finish(struct dbox_sync_context **ctx, bool success);
int dbox_sync(struct dbox_mailbox *mbox);

int dbox_sync_file(struct dbox_sync_context *ctx,
		   const struct dbox_sync_file_entry *entry);
int dbox_sync_index_rebuild(struct dbox_mailbox *mbox);

struct mailbox_sync_context *
dbox_storage_sync_init(struct mailbox *box, enum mailbox_sync_flags flags);

#endif
