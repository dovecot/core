#ifndef __MAIL_INDEX_TRANSACTION_PRIVATE_H
#define __MAIL_INDEX_TRANSACTION_PRIVATE_H

struct mail_index_transaction {
	struct mail_index_view *view;

        buffer_t *appends;
	uint32_t first_new_seq, last_new_seq;

	buffer_t *expunges;

	buffer_t *updates;
        struct mail_transaction_flag_update last_update;
	enum modify_type last_update_modify_type;

	unsigned char hdr_change[sizeof(struct mail_index_header)];
	unsigned char hdr_mask[sizeof(struct mail_index_header)];

	buffer_t *extra_rec_updates[MAIL_INDEX_MAX_EXTRA_RECORDS];

	buffer_t *cache_updates;
	unsigned int hide_transaction:1;
	unsigned int hdr_changed:1;
};

#endif
