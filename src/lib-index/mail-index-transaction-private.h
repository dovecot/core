#ifndef __MAIL_INDEX_TRANSACTION_PRIVATE_H
#define __MAIL_INDEX_TRANSACTION_PRIVATE_H

#include "mail-transaction-log.h"

struct mail_index_transaction {
	int refcount;
	struct mail_index_view *view;

        buffer_t *appends;
	uint32_t first_new_seq, last_new_seq;
	unsigned int append_record_size;

	buffer_t *expunges;

	buffer_t *updates;
        struct mail_transaction_flag_update last_update;
	enum modify_type last_update_modify_type;

	unsigned char hdr_change[sizeof(struct mail_index_header)];
	unsigned char hdr_mask[sizeof(struct mail_index_header)];

	buffer_t *extra_rec_updates[MAIL_INDEX_MAX_EXTRA_RECORDS];

	uint32_t new_cache_file_seq, last_cache_file_seq;
	buffer_t *cache_updates;
        struct mail_cache_transaction_ctx *cache_trans_ctx;

	unsigned int hide_transaction:1;
	unsigned int hdr_changed:1;
};

struct mail_index_record *
mail_index_transaction_lookup(struct mail_index_transaction *t, uint32_t seq);

void mail_index_transaction_ref(struct mail_index_transaction *t);
void mail_index_transaction_unref(struct mail_index_transaction *t);

#endif
