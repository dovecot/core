#ifndef __MAIL_INDEX_VIEW_PRIVATE_H
#define __MAIL_INDEX_VIEW_PRIVATE_H

#include "mail-index-private.h"

struct mail_index_view_methods {
	void (*close)(struct mail_index_view *view);
	uint32_t (*get_message_count)(struct mail_index_view *view);
	int (*get_header)(struct mail_index_view *view,
			  const struct mail_index_header **hdr_r);
	int (*lookup_full)(struct mail_index_view *view, uint32_t seq,
			   struct mail_index_map **map_r,
			   const struct mail_index_record **rec_r);
	int (*lookup_uid)(struct mail_index_view *view, uint32_t seq,
			  uint32_t *uid_r);
	int (*lookup_uid_range)(struct mail_index_view *view,
				uint32_t first_uid, uint32_t last_uid,
				uint32_t *first_seq_r, uint32_t *last_seq_r);
	int (*lookup_first)(struct mail_index_view *view, enum mail_flags flags,
			    uint8_t flags_mask, uint32_t *seq_r);
};

struct mail_index_view {
	struct mail_index_view_methods methods;
	struct mail_index *index;
        struct mail_transaction_log_view *log_view;

	unsigned int indexid;
	struct mail_index_map *map;
	struct mail_index_map *new_map;
	buffer_t *map_refs;

	struct mail_index_header tmp_hdr_copy;
	uint32_t messages_count; /* last synced one, map may be different */

	uint32_t log_file_seq;
	uoff_t log_file_offset;
        buffer_t *log_syncs;

	int transactions;
	unsigned int lock_id;

	unsigned int inconsistent:1;
	unsigned int syncing:1;
	unsigned int external:1;
	unsigned int map_protected:1;
};

void mail_index_view_clone(struct mail_index_view *dest,
			   const struct mail_index_view *src);
int mail_index_view_lock(struct mail_index_view *view);
int mail_index_view_lock_head(struct mail_index_view *view, int update_index);
void mail_index_view_unref_maps(struct mail_index_view *view);
void mail_index_view_add_synced_transaction(struct mail_index_view *view,
					    uint32_t log_file_seq,
					    uoff_t log_file_offset);

#endif
