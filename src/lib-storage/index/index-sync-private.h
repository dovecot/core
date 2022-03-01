#ifndef INDEX_SYNC_PRIVATE_H
#define INDEX_SYNC_PRIVATE_H

#include "index-storage.h"

struct index_mailbox_sync_pvt_context;

struct index_mailbox_sync_context {
	struct mailbox_sync_context ctx;

	struct mail_index_view_sync_ctx *sync_ctx;
	uint32_t messages_count;

	ARRAY_TYPE(seq_range) flag_updates;
	ARRAY_TYPE(seq_range) hidden_updates;
	ARRAY_TYPE(seq_range) all_flag_update_uids;
	const ARRAY_TYPE(seq_range) *expunges;
	unsigned int flag_update_idx, hidden_update_idx, expunge_pos;

	bool failed;
};

void index_sync_search_results_uidify(struct index_mailbox_sync_context *ctx);
void index_sync_search_results_update(struct index_mailbox_sync_context *ctx);
void index_sync_search_results_expunge(struct index_mailbox_sync_context *ctx);

/* Returns 1 = ok, 0 = no private indexes, -1 = error */
int index_mailbox_sync_pvt_init(struct mailbox *box, bool lock,
				enum mail_index_view_sync_flags flags,
				struct index_mailbox_sync_pvt_context **ctx_r);
int index_mailbox_sync_pvt_newmails(struct index_mailbox_sync_pvt_context *ctx,
				    struct mailbox_transaction_context *trans);
int index_mailbox_sync_pvt_view(struct index_mailbox_sync_pvt_context *ctx,
				ARRAY_TYPE(seq_range) *flag_updates,
				ARRAY_TYPE(seq_range) *hidden_updates);
void index_mailbox_sync_pvt_deinit(struct index_mailbox_sync_pvt_context **ctx);

#endif
