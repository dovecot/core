#ifndef __MAIL_INDEX_TRANSACTION_PRIVATE_H
#define __MAIL_INDEX_TRANSACTION_PRIVATE_H

#include "mail-transaction-log.h"

struct mail_index_transaction {
	int refcount;
	struct mail_index_view *view;

        buffer_t *appends;
	uint32_t first_new_seq, last_new_seq;

	buffer_t *expunges;

	buffer_t *updates;
        struct mail_transaction_flag_update last_update;
	enum modify_type last_update_modify_type;

	unsigned char hdr_change[sizeof(struct mail_index_header)];
	unsigned char hdr_mask[sizeof(struct mail_index_header)];

	buffer_t *ext_rec_updates; /* buffer[] */
	buffer_t *ext_resizes; /* struct mail_transaction_ext_intro[] */
	buffer_t *ext_resets; /* uint32_t[] */

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

int mail_index_seq_buffer_lookup(buffer_t *buffer, uint32_t seq,
				 size_t record_size, size_t *pos_r);

#endif
