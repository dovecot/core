#ifndef __MAIL_INDEX_TRANSACTION_PRIVATE_H
#define __MAIL_INDEX_TRANSACTION_PRIVATE_H

#include "mail-transaction-log.h"

struct mail_index_transaction_keyword_update {
	array_t ARRAY_DEFINE(add_seq, uint32_t);
	array_t ARRAY_DEFINE(remove_seq, uint32_t);
};

struct mail_index_transaction {
	int refcount;
	struct mail_index_view *view;

        array_t ARRAY_DEFINE(appends, struct mail_index_record);
	uint32_t first_new_seq, last_new_seq;

	array_t ARRAY_DEFINE(expunges, struct mail_transaction_expunge);
	array_t ARRAY_DEFINE(updates, struct mail_transaction_flag_update);
	size_t last_update_idx;

	unsigned char hdr_change[sizeof(struct mail_index_header)];
	unsigned char hdr_mask[sizeof(struct mail_index_header)];

	array_t ARRAY_DEFINE(ext_rec_updates, array_t);
	array_t ARRAY_DEFINE(ext_resizes, struct mail_transaction_ext_intro);
	array_t ARRAY_DEFINE(ext_resets, uint32_t);

	array_t ARRAY_DEFINE(keyword_updates,
			     struct mail_index_transaction_keyword_update);
	array_t ARRAY_DEFINE(keyword_resets, struct seq_range);

        struct mail_cache_transaction_ctx *cache_trans_ctx;

	unsigned int hide_transaction:1;
	unsigned int no_appends:1;
	unsigned int external:1;
	unsigned int hdr_changed:1;
	unsigned int log_updates:1;
};

struct mail_index_record *
mail_index_transaction_lookup(struct mail_index_transaction *t, uint32_t seq);

void mail_index_transaction_ref(struct mail_index_transaction *t);
void mail_index_transaction_unref(struct mail_index_transaction *t);

int mail_index_seq_array_lookup(const array_t *buffer, uint32_t seq,
				unsigned int *idx_r);

#endif
