#ifndef __MAIL_INDEX_VIEW_PRIVATE_H
#define __MAIL_INDEX_VIEW_PRIVATE_H

#include "mail-index-private.h"

struct mail_index_view_methods {
	void (*close)(struct mail_index_view *view);
	uint32_t (*get_messages_count)(struct mail_index_view *view);
	const struct mail_index_header *
		(*get_header)(struct mail_index_view *view);
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
	int (*lookup_ext_full)(struct mail_index_view *view, uint32_t seq,
			       uint32_t ext_id, struct mail_index_map **map_r,
			       const void **data_r);
	int (*get_header_ext)(struct mail_index_view *view,
			      struct mail_index_map *map, uint32_t ext_id,
			      const void **data_r, size_t *data_size_r);
};

struct mail_index_view {
	int refcount;

	struct mail_index_view_methods methods;
	struct mail_index *index;
        struct mail_transaction_log_view *log_view;

	unsigned int indexid;
	struct mail_index_map *map;
	/* After syncing view, map is replaced with sync_new_map. */
	struct mail_index_map *sync_new_map;
	/* All mappings where we have returned records. They need to be kept
	   valid until view is synchronized. */
	array_t ARRAY_DEFINE(map_refs, struct mail_index_map *);

	struct mail_index_header hdr;

	uint32_t log_file_seq;
	uoff_t log_file_offset;
	/* Contains a list of transaction log offsets which we don't want to
	   return when syncing. */
	array_t ARRAY_DEFINE(log_syncs, struct mail_index_view_log_sync_pos);

	int transactions;
	unsigned int lock_id;

	unsigned int inconsistent:1;
	unsigned int syncing:1;
};

void mail_index_view_clone(struct mail_index_view *dest,
			   const struct mail_index_view *src);
void mail_index_view_ref(struct mail_index_view *view);
int mail_index_view_lock(struct mail_index_view *view);
int mail_index_view_lock_head(struct mail_index_view *view, bool update_index);
void mail_index_view_unref_maps(struct mail_index_view *view);
void mail_index_view_add_synced_transaction(struct mail_index_view *view,
					    uint32_t log_file_seq,
					    uoff_t log_file_offset);

struct mail_index_view *mail_index_dummy_view_open(struct mail_index *index);

#endif
