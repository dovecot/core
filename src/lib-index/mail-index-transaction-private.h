#ifndef __MAIL_INDEX_TRANSACTION_PRIVATE_H
#define __MAIL_INDEX_TRANSACTION_PRIVATE_H

struct mail_index_transaction {
	struct mail_index_view *view;

        buffer_t *appends;
	uint32_t first_new_seq, last_new_seq, next_uid;

	buffer_t *expunges;

	buffer_t *updates;
        struct mail_transaction_flag_update last_update;
	enum modify_type last_update_modify_type;

	buffer_t *cache_updates;
	unsigned int hide_transaction:1;
};

#endif
