#ifndef MAIL_INDEX_VIEW_PRIVATE_H
#define MAIL_INDEX_VIEW_PRIVATE_H

#include "mail-index-private.h"

struct mail_index_view_log_sync_area {
	uint32_t log_file_seq;
	unsigned int length;
	uoff_t log_file_offset;
};
ARRAY_DEFINE_TYPE(view_log_sync_area, struct mail_index_view_log_sync_area);

struct mail_index_view_vfuncs {
	void (*close)(struct mail_index_view *view);
	uint32_t (*get_messages_count)(struct mail_index_view *view);
	const struct mail_index_header *
		(*get_header)(struct mail_index_view *view);
	const struct mail_index_record *
		(*lookup_full)(struct mail_index_view *view, uint32_t seq,
			       struct mail_index_map **map_r, bool *expunged_r);
	void (*lookup_uid)(struct mail_index_view *view, uint32_t seq,
			   uint32_t *uid_r);
	void (*lookup_seq_range)(struct mail_index_view *view,
				 uint32_t first_uid, uint32_t last_uid,
				 uint32_t *first_seq_r, uint32_t *last_seq_r);
	void (*lookup_first)(struct mail_index_view *view,
			     enum mail_flags flags, uint8_t flags_mask,
			     uint32_t *seq_r);
	void (*lookup_keywords)(struct mail_index_view *view, uint32_t seq,
				ARRAY_TYPE(keyword_indexes) *keyword_idx);
	void (*lookup_ext_full)(struct mail_index_view *view, uint32_t seq,
				uint32_t ext_id, struct mail_index_map **map_r,
				const void **data_r, bool *expunged_r);
	void (*get_header_ext)(struct mail_index_view *view,
			       struct mail_index_map *map, uint32_t ext_id,
			       const void **data_r, size_t *data_size_r);
	bool (*ext_get_reset_id)(struct mail_index_view *view,
				 struct mail_index_map *map,
				 uint32_t ext_id, uint32_t *reset_id_r);
};

union mail_index_view_module_context {
	struct mail_index_module_register *reg;
};

struct mail_index_view {
	struct mail_index_view *prev, *next;
	int refcount;

	struct mail_index_view_vfuncs v;
	struct mail_index *index;
        struct mail_transaction_log_view *log_view;

	const char *source_filename;
	unsigned int source_linenum;

	uint32_t indexid;
	unsigned int inconsistency_id;
	uint64_t highest_modseq;

	struct mail_index_map *map;
	/* All mappings where we have returned records. They need to be kept
	   valid until view is synchronized. */
	ARRAY(struct mail_index_map *) map_refs;

	/* expunge <= head */
	uint32_t log_file_expunge_seq, log_file_head_seq;
	uoff_t log_file_expunge_offset, log_file_head_offset;

	/* Transaction log offsets which we don't want to return in view sync */
	ARRAY_TYPE(view_log_sync_area) syncs_hidden;

	/* Module-specific contexts. */
	ARRAY(union mail_index_view_module_context *) module_contexts;

	struct mail_index_transaction *transactions_list;
	int transactions;

	bool inconsistent:1;
	/* this view was created by mail_index_sync_begin() */
	bool index_sync_view:1;
	/* this view is being synced */
	bool syncing:1;
};

struct mail_index_view *
mail_index_view_open_with_map(struct mail_index *index,
			      struct mail_index_map *map);
void mail_index_view_clone(struct mail_index_view *dest,
			   const struct mail_index_view *src,
			   const char *source_filename,
			   unsigned int source_linenum);
#define mail_index_view_clone(dest, src) \
	mail_index_view_clone(dest, src, __FILE__, __LINE__)

struct mail_index_view *
mail_index_view_dup_private(const struct mail_index_view *src,
			    const char *source_filename,
			    unsigned int source_linenum);
#define mail_index_view_dup_private(src) \
	mail_index_view_dup_private(src, __FILE__, __LINE__)
void mail_index_view_ref(struct mail_index_view *view);
void mail_index_view_unref_maps(struct mail_index_view *view);
void mail_index_view_add_hidden_transaction(struct mail_index_view *view,
					    uint32_t log_file_seq,
					    uoff_t log_file_offset,
					    unsigned int length);

struct mail_index_view *mail_index_dummy_view_open(struct mail_index *index);

#endif
