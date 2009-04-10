#ifndef DBOX_SYNC_H
#define DBOX_SYNC_H

struct mailbox;
struct dbox_mailbox;

enum dbox_sync_flags {
	DBOX_SYNC_FLAG_FORCE		= 0x01,
	DBOX_SYNC_FLAG_FSYNC		= 0x02,
	DBOX_SYNC_FLAG_FORCE_REBUILD	= 0x04
};

struct dbox_sync_file_entry {
	uint32_t uid, file_id;

	unsigned int move_from_alt:1;
	unsigned int move_to_alt:1;
	ARRAY_TYPE(seq_range) expunge_seqs;
	ARRAY_TYPE(uint32_t) expunge_map_uids;
};

struct dbox_sync_context {
	struct dbox_mailbox *mbox;
        struct mail_index_sync_ctx *index_sync_ctx;
	struct mail_index_view *sync_view;
	struct mail_index_transaction *trans;
	struct dbox_map_transaction_context *map_trans;

	string_t *path;
	unsigned int path_dir_prefix_len;

	pool_t pool;
	struct hash_table *syncs; /* struct dbox_sync_file_entry */

	unsigned int have_storage_expunges:1;
	unsigned int purge:1;
};

int dbox_sync_begin(struct dbox_mailbox *mbox, enum dbox_sync_flags flags,
		    struct dbox_sync_context **ctx_r);
int dbox_sync_finish(struct dbox_sync_context **ctx, bool success);
int dbox_sync(struct dbox_mailbox *mbox, enum dbox_sync_flags flags);

int dbox_sync_purge(struct mail_storage *storage);
int dbox_sync_file(struct dbox_sync_context *ctx,
		   const struct dbox_sync_file_entry *entry);
int dbox_sync_file_purge(struct dbox_file *file);

struct dbox_sync_rebuild_context *
dbox_sync_index_rebuild_init(struct dbox_mailbox *mbox,
			     struct mail_index_view *view,
			     struct mail_index_transaction *trans,
			     bool storage_rebuild);
int dbox_sync_index_rebuild_singles(struct dbox_sync_rebuild_context *ctx);
void dbox_sync_rebuild_index_metadata(struct dbox_sync_rebuild_context *ctx,
				      struct dbox_file *file,
				      uint32_t new_seq, uint32_t uid);
void dbox_sync_index_rebuild_deinit(struct dbox_sync_rebuild_context **ctx);

int dbox_sync_index_rebuild(struct dbox_mailbox *mbox);

struct mailbox_sync_context *
dbox_storage_sync_init(struct mailbox *box, enum mailbox_sync_flags flags);

#endif
