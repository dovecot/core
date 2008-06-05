#ifndef INDEX_SYNC_PRIVATE_H
#define INDEX_SYNC_PRIVATE_H

#include "index-storage.h"

struct index_mailbox_sync_context {
	struct mailbox_sync_context ctx;
	struct index_mailbox *ibox;
	struct mail_index_view_sync_ctx *sync_ctx;
	uint32_t messages_count;

	ARRAY_TYPE(seq_range) flag_updates;
	ARRAY_TYPE(seq_range) modseq_updates;
	const ARRAY_TYPE(seq_range) *expunges;
	unsigned int flag_update_idx, modseq_update_idx, expunge_pos;

	bool failed;
};

void index_sync_search_results_update(struct index_mailbox_sync_context *ctx);
void index_sync_search_results_expunge(struct index_mailbox_sync_context *ctx);

#endif
