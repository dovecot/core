#ifndef __MAIL_INDEX_SYNC_PRIVATE_H
#define __MAIL_INDEX_SYNC_PRIVATE_H

struct mail_index_sync_ctx {
	struct mail_index *index;
	struct mail_index_view *view;

	buffer_t *expunges_buf, *updates_buf;

	const struct mail_transaction_expunge *expunges;
	const struct mail_transaction_flag_update *updates;
	size_t expunges_count, updates_count;

	uint32_t append_uid_first, append_uid_last;

	const struct mail_transaction_header *hdr;
	const void *data;

	size_t expunge_idx, update_idx;
	uint32_t next_uid;

	unsigned int lock_id;

	unsigned int sync_appends:1;
	unsigned int sync_dirty:1;
};

struct mail_index_expunge_handler {
	mail_index_expunge_handler_t *handler;
	void **context;
	uint32_t record_offset;
};

struct mail_index_sync_map_ctx {
	struct mail_index_view *view;
	uint32_t cur_ext_id;

	buffer_t *expunge_handlers; /* struct mail_index_expunge_handler[] */

	buffer_t *extra_context_buf;
	void **extra_context;

        enum mail_index_sync_handler_type type;

	unsigned int sync_handlers_initialized:1;
	unsigned int expunge_handlers_set:1;
	unsigned int expunge_handlers_used:1;
	unsigned int cur_ext_ignore:1;
};

extern struct mail_transaction_map_functions mail_index_map_sync_funcs;

void mail_index_sync_map_init(struct mail_index_sync_map_ctx *sync_map_ctx,
			      struct mail_index_view *view,
			      enum mail_index_sync_handler_type type);
void mail_index_sync_map_deinit(struct mail_index_sync_map_ctx *sync_map_ctx);
int mail_index_sync_update_index(struct mail_index_sync_ctx *sync_ctx,
				 int sync_only_external);

int mail_index_sync_record(struct mail_index_sync_map_ctx *ctx,
			   const struct mail_transaction_header *hdr,
			   const void *data);

void
mail_index_sync_get_expunge(struct mail_index_sync_rec *rec,
			    const struct mail_transaction_expunge *exp);
void
mail_index_sync_get_update(struct mail_index_sync_rec *rec,
			   const struct mail_transaction_flag_update *update);

#endif
