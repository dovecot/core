#ifndef DBOX_SYNC_REBUILD_H
#define DBOX_SYNC_REBUILD_H

struct mailbox_list;

struct dbox_sync_rebuild_context {
	struct mailbox *box;

	struct mail_index_view *view;
	struct mail_index_transaction *trans;
	uint32_t cache_ext_id;
	uint32_t cache_reset_id;

	struct mail_index *backup_index;
	struct mail_index_view *backup_view;

	unsigned int cache_used:1;
};

struct dbox_sync_rebuild_context *
dbox_sync_index_rebuild_init(struct mailbox *box,
			     struct mail_index_view *view,
			     struct mail_index_transaction *trans);
void dbox_sync_index_rebuild_deinit(struct dbox_sync_rebuild_context **ctx);

void dbox_sync_rebuild_index_metadata(struct dbox_sync_rebuild_context *ctx,
				      uint32_t new_seq, uint32_t uid);
int dbox_sync_rebuild_verify_alt_storage(struct mailbox_list *list);

#endif
