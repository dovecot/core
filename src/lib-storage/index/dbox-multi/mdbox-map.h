#ifndef MDBOX_MAP_H
#define MDBOX_MAP_H

#include "seq-range-array.h"

struct dbox_map_append_context;
struct dbox_file_append_context;
struct mdbox_storage;

enum dbox_map_append_flags {
	DBOX_MAP_APPEND_FLAG_ALT	= 0x01
};

struct dbox_map_mail_index_header {
	uint32_t highest_file_id;
};

struct dbox_map_mail_index_record {
	uint32_t file_id;
	uint32_t offset;
	uint32_t size; /* including pre/post metadata */
};

struct dbox_map_file_msg {
	uint32_t map_uid;
	uint32_t offset;
	uint32_t refcount;
};
ARRAY_DEFINE_TYPE(dbox_map_file_msg, struct dbox_map_file_msg);

struct dbox_map *
dbox_map_init(struct mdbox_storage *storage, struct mailbox_list *root_list,
	      const char *path);
void dbox_map_deinit(struct dbox_map **map);

/* Open the map. Returns 1 if ok, 0 if map doesn't exist, -1 if error. */
int dbox_map_open(struct dbox_map *map);
/* Open or create the map. This is done automatically for most operations.
   Returns 0 if ok, -1 if error. */
int dbox_map_open_or_create(struct dbox_map *map);
/* Refresh the map. Returns 0 if ok, -1 if error. */
int dbox_map_refresh(struct dbox_map *map);

/* Look up file_id and offset for given map UID. Returns 1 if ok, 0 if UID
   is already expunged, -1 if error. */
int dbox_map_lookup(struct dbox_map *map, uint32_t map_uid,
		    uint32_t *file_id_r, uoff_t *offset_r);
/* Like dbox_map_lookup(), but look up everything. */
int dbox_map_lookup_full(struct dbox_map *map, uint32_t map_uid,
			 struct dbox_map_mail_index_record *rec_r,
			 uint16_t *refcount_r);

/* Get all messages from file */
int dbox_map_get_file_msgs(struct dbox_map *map, uint32_t file_id,
			   ARRAY_TYPE(dbox_map_file_msg) *recs);

struct dbox_map_transaction_context *
dbox_map_transaction_begin(struct dbox_map *map, bool external);
/* Write transaction to map and leave it locked. Call _free() to update tail
   offset and unlock. */
int dbox_map_transaction_commit(struct dbox_map_transaction_context *ctx);
void dbox_map_transaction_set_failed(struct dbox_map_transaction_context *ctx);
void dbox_map_transaction_free(struct dbox_map_transaction_context **ctx);

int dbox_map_update_refcount(struct dbox_map_transaction_context *ctx,
			     uint32_t map_uid, int diff);
int dbox_map_update_refcounts(struct dbox_map_transaction_context *ctx,
			      const ARRAY_TYPE(uint32_t) *map_uids, int diff);
int dbox_map_remove_file_id(struct dbox_map *map, uint32_t file_id);

/* Return all files containing messages with zero refcount. */
int dbox_map_get_zero_ref_files(struct dbox_map *map,
				ARRAY_TYPE(seq_range) *file_ids_r);

struct dbox_map_append_context *
dbox_map_append_begin(struct dbox_map *map);
/* Request file for saving a new message with given size (if available). If an
   existing file can be used, the record is locked and updated in index.
   Returns 0 if ok, -1 if error. */
int dbox_map_append_next(struct dbox_map_append_context *ctx, uoff_t mail_size,
			 enum dbox_map_append_flags flags,
			 struct dbox_file_append_context **file_append_ctx_r,
			 struct ostream **output_r);
/* Finished saving the last mail. Saves the message size. */
void dbox_map_append_finish(struct dbox_map_append_context *ctx);
/* Assign map UIDs to all appended msgs to multi-files. */
int dbox_map_append_assign_map_uids(struct dbox_map_append_context *ctx,
				    uint32_t *first_map_uid_r,
				    uint32_t *last_map_uid_r);
/* The appends are existing messages that were simply moved to a new file.
   map_uids contains the moved messages' map UIDs. */
int dbox_map_append_move(struct dbox_map_append_context *ctx,
			 const ARRAY_TYPE(uint32_t) *map_uids,
			 const ARRAY_TYPE(seq_range) *expunge_map_uids);
/* Returns 0 if ok, -1 if error. */
int dbox_map_append_commit(struct dbox_map_append_context *ctx);
void dbox_map_append_free(struct dbox_map_append_context **ctx);

/* Get either existing uidvalidity or create a new one if map was
   just created. */
uint32_t dbox_map_get_uid_validity(struct dbox_map *map);

void dbox_map_set_corrupted(struct dbox_map *map, const char *format, ...)
	ATTR_FORMAT(2, 3);

#endif
