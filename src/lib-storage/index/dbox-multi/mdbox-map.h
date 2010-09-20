#ifndef MDBOX_MAP_H
#define MDBOX_MAP_H

#include "seq-range-array.h"

struct dbox_file_append_context;
struct mdbox_map_append_context;
struct mdbox_storage;

enum mdbox_map_append_flags {
	DBOX_MAP_APPEND_FLAG_ALT	= 0x01
};

struct mdbox_map_mail_index_header {
	uint32_t highest_file_id;
	/* increased every time storage is rebuilt */
	uint32_t rebuild_count;
};

struct mdbox_map_mail_index_record {
	uint32_t file_id;
	uint32_t offset;
	uint32_t size; /* including pre/post metadata */
};

struct mdbox_map_file_msg {
	uint32_t map_uid;
	uint32_t offset;
	uint32_t refcount;
};
ARRAY_DEFINE_TYPE(mdbox_map_file_msg, struct mdbox_map_file_msg);

struct mdbox_map *
mdbox_map_init(struct mdbox_storage *storage, struct mailbox_list *root_list);
void mdbox_map_deinit(struct mdbox_map **map);

/* Open the map. Returns 1 if ok, 0 if map doesn't exist, -1 if error. */
int mdbox_map_open(struct mdbox_map *map);
/* Open or create the map. This is done automatically for most operations.
   Returns 0 if ok, -1 if error. */
int mdbox_map_open_or_create(struct mdbox_map *map);
/* Refresh the map. Returns 0 if ok, -1 if error. */
int mdbox_map_refresh(struct mdbox_map *map);

/* Return the current rebuild counter */
uint32_t mdbox_map_get_rebuild_count(struct mdbox_map *map);

/* Look up file_id and offset for given map UID. Returns 1 if ok, 0 if UID
   is already expunged, -1 if error. */
int mdbox_map_lookup(struct mdbox_map *map, uint32_t map_uid,
		     uint32_t *file_id_r, uoff_t *offset_r);
/* Like mdbox_map_lookup(), but look up everything. */
int mdbox_map_lookup_full(struct mdbox_map *map, uint32_t map_uid,
			  struct mdbox_map_mail_index_record *rec_r,
			  uint16_t *refcount_r);

/* Get all messages from file */
int mdbox_map_get_file_msgs(struct mdbox_map *map, uint32_t file_id,
			    ARRAY_TYPE(mdbox_map_file_msg) *recs);

/* Begin atomic context. There can be multiple transactions/appends within the
   same atomic context. */
struct mdbox_map_atomic_context *mdbox_map_atomic_begin(struct mdbox_map *map);
/* Lock the map immediately. */
int mdbox_map_atomic_lock(struct mdbox_map_atomic_context *atomic);
/* Returns TRUE if map is locked */
bool mdbox_map_atomic_is_locked(struct mdbox_map_atomic_context *atomic);
/* When finish() is called, rollback the changes. If data was already written
   to map's transaction log, this desyncs the map and causes a rebuild */
void mdbox_map_atomic_set_failed(struct mdbox_map_atomic_context *atomic);
/* Mark this atomic as having succeeded. This is internally done if
   transaction or append is committed within this atomic, but not when the
   atomic is used standalone. */
void mdbox_map_atomic_set_success(struct mdbox_map_atomic_context *atomic);
/* Commit/rollback changes within this atomic context. */
int mdbox_map_atomic_finish(struct mdbox_map_atomic_context **atomic);

struct mdbox_map_transaction_context *
mdbox_map_transaction_begin(struct mdbox_map_atomic_context *atomic,
			    bool external);
/* Write transaction to map and leave it locked. Call _free() to update tail
   offset and unlock. */
int mdbox_map_transaction_commit(struct mdbox_map_transaction_context *ctx);
void mdbox_map_transaction_free(struct mdbox_map_transaction_context **ctx);

int mdbox_map_update_refcount(struct mdbox_map_transaction_context *ctx,
			      uint32_t map_uid, int diff);
int mdbox_map_update_refcounts(struct mdbox_map_transaction_context *ctx,
			       const ARRAY_TYPE(uint32_t) *map_uids, int diff);
int mdbox_map_remove_file_id(struct mdbox_map *map, uint32_t file_id);

/* Return all files containing messages with zero refcount. */
int mdbox_map_get_zero_ref_files(struct mdbox_map *map,
				 ARRAY_TYPE(seq_range) *file_ids_r);

struct mdbox_map_append_context *
mdbox_map_append_begin(struct mdbox_map_atomic_context *atomic);
/* Request file for saving a new message with given size (if available). If an
   existing file can be used, the record is locked and updated in index.
   Returns 0 if ok, -1 if error. */
int mdbox_map_append_next(struct mdbox_map_append_context *ctx, uoff_t mail_size,
			  enum mdbox_map_append_flags flags,
			  struct dbox_file_append_context **file_append_ctx_r,
			  struct ostream **output_r);
/* Finished saving the last mail. Saves the message size. */
void mdbox_map_append_finish(struct mdbox_map_append_context *ctx);
/* Abort saving the last mail. */
void mdbox_map_append_abort(struct mdbox_map_append_context *ctx);
/* Assign map UIDs to all appended msgs to multi-files. */
int mdbox_map_append_assign_map_uids(struct mdbox_map_append_context *ctx,
				     uint32_t *first_map_uid_r,
				     uint32_t *last_map_uid_r);
/* The appends are existing messages that were simply moved to a new file.
   map_uids contains the moved messages' map UIDs. */
int mdbox_map_append_move(struct mdbox_map_append_context *ctx,
			  const ARRAY_TYPE(uint32_t) *map_uids,
			  const ARRAY_TYPE(seq_range) *expunge_map_uids);
/* Returns 0 if ok, -1 if error. */
int mdbox_map_append_commit(struct mdbox_map_append_context *ctx);
void mdbox_map_append_free(struct mdbox_map_append_context **ctx);

/* Returns map's uidvalidity */
uint32_t mdbox_map_get_uid_validity(struct mdbox_map *map);

void mdbox_map_set_corrupted(struct mdbox_map *map, const char *format, ...)
	ATTR_FORMAT(2, 3);

#endif
