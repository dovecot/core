#ifndef INDEX_REBUILD_H
#define INDEX_REBUILD_H

struct mailbox_list;

struct index_rebuild_context {
	struct mailbox *box;

	struct mail_index_view *view;
	struct mail_index_transaction *trans;
	uint32_t cache_ext_id;
	uint32_t cache_reset_id;

	struct mail_index *backup_index;
	struct mail_index_view *backup_view;

	unsigned int cache_used:1;
};

typedef unsigned int
index_rebuild_generate_uidvalidity_t(struct mailbox_list *list);

struct index_rebuild_context *
index_index_rebuild_init(struct mailbox *box, struct mail_index_view *view,
			 struct mail_index_transaction *trans);
void index_index_rebuild_deinit(struct index_rebuild_context **ctx,
				index_rebuild_generate_uidvalidity_t *cb);

void index_rebuild_index_metadata(struct index_rebuild_context *ctx,
				  uint32_t new_seq, uint32_t uid);

#endif
