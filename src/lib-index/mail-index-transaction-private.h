#ifndef __MAIL_INDEX_TRANSACTION_PRIVATE_H
#define __MAIL_INDEX_TRANSACTION_PRIVATE_H

#include "mail-transaction-log.h"

struct mail_keyword_transaction {
	/* mail_keywords points to first mail_index_keyword_transaction.
	   this points to next keyword transaction using the same keywords */
	struct mail_keyword_transaction *next;

	enum modify_type modify_type;
	struct mail_index_transaction *transaction;

	struct mail_keywords *keywords;
	buffer_t *messages;
};

struct mail_index_transaction {
	int refcount;
	struct mail_index_view *view;

        buffer_t *appends;
	uint32_t first_new_seq, last_new_seq;

	buffer_t *expunges;

	buffer_t *updates;
	size_t last_update_idx;

	unsigned char hdr_change[sizeof(struct mail_index_header)];
	unsigned char hdr_mask[sizeof(struct mail_index_header)];

	buffer_t *ext_rec_updates; /* buffer[] */
	buffer_t *ext_resizes; /* struct mail_transaction_ext_intro[] */
	buffer_t *ext_resets; /* uint32_t[] */
	buffer_t *keyword_updates; /* struct mail_keyword_transaction[] */

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
