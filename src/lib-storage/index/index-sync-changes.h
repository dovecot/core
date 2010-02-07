#ifndef INDEX_SYNC_CHANGES_H
#define INDEX_SYNC_CHANGES_H

struct index_sync_changes_context *
index_sync_changes_init(struct mail_index_sync_ctx *index_sync_ctx,
			struct mail_index_view *sync_view,
			struct mail_index_transaction *sync_trans,
			bool dirty_flag_updates);
void index_sync_changes_deinit(struct index_sync_changes_context **_ctx);

void index_sync_changes_reset(struct index_sync_changes_context *ctx);
void index_sync_changes_delete_to(struct index_sync_changes_context *ctx,
				  uint32_t last_uid);

void index_sync_changes_read(struct index_sync_changes_context *ctx,
			     uint32_t uid, bool *sync_expunge_r,
			     uint8_t expunged_guid_128[MAIL_GUID_128_SIZE]);
bool index_sync_changes_have(struct index_sync_changes_context *ctx);
uint32_t
index_sync_changes_get_next_uid(struct index_sync_changes_context *ctx);

void index_sync_changes_apply(struct index_sync_changes_context *ctx,
			      pool_t pool, uint8_t *flags,
			      ARRAY_TYPE(keyword_indexes) *keywords,
			      enum mail_index_sync_type *sync_type_r);

#endif
