#ifndef __MAIL_INDEX_VIEW_PRIVATE_H
#define __MAIL_INDEX_VIEW_PRIVATE_H

#include "mail-index-private.h"

struct mail_index_view {
	struct mail_index *index;
        struct mail_transaction_log_view *log_view;

	struct mail_index_map *map;

	uint32_t log_file_seq;
	uoff_t log_file_offset;
        buffer_t *log_syncs;

	int transactions;
	unsigned int lock_id;

	unsigned int inconsistent:1;
	unsigned int syncing:1;
	unsigned int external:1;
};

int mail_index_view_lock(struct mail_index_view *view);
int mail_index_view_lock_head(struct mail_index_view *view, int update_index);
void mail_index_view_add_synced_transaction(struct mail_index_view *view,
					    uint32_t log_file_seq,
					    uoff_t log_file_offset);

#endif
