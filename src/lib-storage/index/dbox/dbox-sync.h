#ifndef DBOX_SYNC_H
#define DBOX_SYNC_H

struct mailbox;

struct dbox_sync_file_entry {
	uint32_t file_id;

	ARRAY_TYPE(seq_range) changes;
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
	ARRAY_TYPE(seq_range) expunge_files;
	ARRAY_TYPE(seq_range) locked_files;

	unsigned int flush_dirty_flags:1;
};

int dbox_sync_begin(struct dbox_mailbox *mbox,
		    struct dbox_sync_context **ctx_r,
		    bool close_flush_dirty_flags);
int dbox_sync_finish(struct dbox_sync_context **ctx, bool success);
int dbox_sync(struct dbox_mailbox *mbox, bool close_flush_dirty_flags);

int dbox_sync_file(struct dbox_sync_context *ctx,
		   const struct dbox_sync_file_entry *entry);
int dbox_sync_index_rebuild(struct dbox_mailbox *mbox);

struct mailbox_sync_context *
dbox_storage_sync_init(struct mailbox *box, enum mailbox_sync_flags flags);

#endif
