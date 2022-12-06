#ifndef MAIL_CACHE_PRIVATE_H
#define MAIL_CACHE_PRIVATE_H

#include "file-dotlock.h"
#include "mail-index-private.h"
#include "mail-cache.h"

#define MAIL_CACHE_MAJOR_VERSION 1
#define MAIL_CACHE_MINOR_VERSION 1

#define MAIL_CACHE_LOCK_TIMEOUT 10
#define MAIL_CACHE_LOCK_CHANGE_TIMEOUT 300

#define MAIL_CACHE_MAX_WRITE_BUFFER (1024*256)

#define MAIL_CACHE_IS_UNUSABLE(cache) \
	((cache)->hdr == NULL)

struct mail_cache_header {
	/* Major version is increased only when you can't have backwards
	   compatibility. If the field doesn't match MAIL_CACHE_MAJOR_VERSION,
	   don't even try to read it. */
	uint8_t major_version;
	/* If this isn't the same as sizeof(uoff_t), the cache file can't be
	   safely used with the current implementation. */
	uint8_t compat_sizeof_uoff_t;
	/* Minor version is increased when the file format changes in a
	   backwards compatible way. */
	uint8_t minor_version;
	uint8_t unused;

	/* Unique index file ID, which must match the main index's indexid.
	   See mail_index_header.indexid. */
	uint32_t indexid;
	/* Cache file sequence. Increased on every purge. This must match the
	   main index's reset_id for "cache" extension or the cache offsets
	   aren't valid. When creating the first cache file, use the current
	   UNIX timestamp as the file_seq. */
	uint32_t file_seq;

	/* Number of cache records that are linked inside the cache file,
	   instead of being directly pointed from the main index. */
	uint32_t continued_record_count;

	/* Number of messages cached in this file. This does not include
	   the continuation records.

	   NOTE: <=v2.1 used this for hole offset, so we can't fully
	   rely on it */
	uint32_t record_count;
	/* Currently unused. */
	uint32_t backwards_compat_used_file_size;
	/* Number of already expunged messages that currently have cache
	   content in this file. */
	uint32_t deleted_record_count;

	/* Offset to the first mail_cache_header_fields. */
	uint32_t field_header_offset;
};

struct mail_cache_header_fields {
	/* Offset to the updated version of this header. Use
	   mail_index_offset_to_uint32() to decode it. */
	uint32_t next_offset;
	/* Full size of this header. */
	uint32_t size;
	/* Number of fields in this header. */
	uint32_t fields_count;

#if 0
	/* Last time the field was accessed. Not updated more often than
	   once a day. This field may be overwritten later on, which in theory
	   could cause reading to see a partially updated (corrupted) value.
	   Don't fully trust this field unless it was read while cache is
	   locked. */
	uint32_t last_used[fields_count];
	/* (uint32_t)-1 for variable sized fields */
	uint32_t size[fields_count];
	/* enum mail_cache_field_type */
	uint8_t type[fields_count];
	/* enum mail_cache_decision_type. This field can be overwritten
	   later on to update the caching decision. */
	uint8_t decision[fields_count];
	/* NUL-separated list of field names */
	char name[fields_count][];
#endif
};

/* Macros to return offsets to the fields in mail_cache_header_fields. */
#define MAIL_CACHE_FIELD_LAST_USED() \
	(sizeof(uint32_t) * 3)
#define MAIL_CACHE_FIELD_SIZE(count) \
	(MAIL_CACHE_FIELD_LAST_USED() + sizeof(uint32_t) * (count))
#define MAIL_CACHE_FIELD_TYPE(count) \
	(MAIL_CACHE_FIELD_SIZE(count) + sizeof(uint32_t) * (count))
#define MAIL_CACHE_FIELD_DECISION(count) \
	(MAIL_CACHE_FIELD_TYPE(count) + sizeof(uint8_t) * (count))
#define MAIL_CACHE_FIELD_NAMES(count) \
	(MAIL_CACHE_FIELD_DECISION(count) + sizeof(uint8_t) * (count))

struct mail_cache_record {
	uint32_t prev_offset;
	uint32_t size; /* full record size, including this header */
	/* array of { uint32_t field; [ uint32_t size; ] { .. } } */
};

struct mail_cache_field_private {
	struct mail_cache_field field;

	/* Highest message UID whose cache field of this type have been
	   accessed within this session. This is used to track whether messages
	   are accessed in non-ascending order, which indicates an IMAP client
	   that doesn't have a local cache. That will result in the caching
	   decision to change from TEMP to YES. */
	uint32_t uid_highwater;

	/* Unused fields aren't written to cache file */
	bool used:1;
	/* field.decision is pending a write to cache file header. If the
	   cache header is read from disk, don't overwrite it. */
	bool decision_dirty:1;
};

struct mail_cache {
	struct mail_index *index;
	struct event *event;
	/* Registered "cache" extension ID */
	uint32_t ext_id;

	char *filepath;
	int fd;

	struct dotlock_settings dotlock_settings;
	struct file_lock *file_lock;

	/* Cache file's inode, device and size when it was last fstat()ed. */
	ino_t st_ino;
	dev_t st_dev;
	uoff_t last_stat_size;

	/* Used to avoid logging mmap() errors too rapidly. */
	time_t last_mmap_error_time;

	/* a) mmaping the whole file */
	void *mmap_base;
	/* b) using file cache */
	struct file_cache *file_cache;
	/* c) using small read() calls with MAIL_INDEX_OPEN_FLAG_SAVEONLY */
	uoff_t read_offset;
	buffer_t *read_buf;
	/* Size of the cache file as currently mapped to memory. Used for all
	   of a), b), and c). */
	size_t mmap_length;
	/* mail_cache_map() increases this always. Used only for asserts. */
	unsigned int remap_counter;
	/* Linked list of all cache views. */
	struct mail_cache_view *views;

	/* mmap_disable=no: hdr points to data / NULL when cache is invalid.
	   mmap_disable=yes: hdr points to hdr_ro_copy. this is needed because
	   cache invalidation can zero the data any time */
	const struct mail_cache_header *hdr;
	struct mail_cache_header hdr_ro_copy;
	/* hdr_copy gets updated when cache is locked and written when
	   unlocking and hdr_modified=TRUE */
	struct mail_cache_header hdr_copy;
	/* If non-0, the offset for the last seen mail_cache_header_fields.
	   Used as a cache to avoid reading through multiple next_offset
	   pointers. */
	uint32_t last_field_header_offset;

	/* Memory pool used for permanent field allocations. Currently this
	   means mail_cache_field.name and field_name_hash. */
	pool_t field_pool;
	/* Size of fields[] and field_file_map[] */
	unsigned int fields_count;
	/* All the registered cache fields. */
	struct mail_cache_field_private *fields;
	/* mail_cache_field.idx -> file-specific header index. The reverse
	   of this is file_field_map[]. */
	uint32_t *field_file_map;
	/* mail_cache_field.name -> mail_cache_field.idx */
	HASH_TABLE(char *, void *) field_name_hash; /* name -> idx */

	/* file-specific header index -> mail_cache_fields.idx. The reverse
	   of this is field_file_map[]. */
	unsigned int *file_field_map;
	/* Size of file_field_map[] */
	unsigned int file_fields_count;

	/* mail_cache_purge_later() sets these values to trigger purging on
	   the next index sync. need_purge_file_seq is set to the current
	   cache file_seq. If at sync time the file_seq differs, it means
	   the cache was already purged and another purge isn't necessary. */
	uint32_t need_purge_file_seq;
	/* Human-readable reason for purging. Used for debugging and events. */
	char *need_purge_reason;

	/* Cache has been opened (or it doesn't exist). */
	bool opened:1;
	/* Cache has been locked with mail_cache_lock(). */
	bool locked:1;
	/* TRUE if the last lock attempt failed. The next locking attempt will
	   be non-blocking to avoid unnecessarily waiting on a cache that has
	   been locked for a long time. Since cache isn't strictly required,
	   this could avoid unnecessarily long waits with some edge cases. */
	bool last_lock_failed:1;
	/* cache->hdr_copy has been modified. This must be used only while
	   cache is locked. */
	bool hdr_modified:1;
	/* At least one of the cache fields' last_used or cache decision has
	   changed. mail_cache_header_fields_update() will be used to overwrite
	   these to the latest mail_cache_header_fields. */
	bool field_header_write_pending:1;
	/* Cache is currently being purged. */
	bool purging:1;
	/* Access the cache file by reading as little as possible from it
	   (as opposed to mmap()ing it or using file-cache.h API to cache
	   larger parts of it). This is used with MAIL_INDEX_OPEN_FLAG_SAVEONLY
	   to avoid unnecessary cache reads. */
	bool map_with_read:1;
	/* Cache headers count has been capped */
	bool headers_capped:1;
};

struct mail_cache_loop_track {
	/* we're looping if size_sum > (max_offset-min_offset) */
	uoff_t min_offset, max_offset;
	uoff_t size_sum;
};

struct mail_cache_missing_reason_cache {
	uint32_t highest_checked_seq;
	uint32_t highest_seq_with_cache;

	uint32_t reset_id;
	uint32_t log_file_head_seq;
	uoff_t log_file_head_offset;
};

struct mail_cache_view {
	struct mail_cache *cache;
	struct mail_cache_view *prev, *next;
	struct mail_index_view *view, *trans_view;

	struct mail_cache_transaction_ctx *transaction;
	/* mail_cache_add() has been called for some of the messages between
	   trans_seq1..trans_seq2 in an uncommitted transaction. Check also
	   the transaction contents when looking up cache fields for these
	   mails. */
	uint32_t trans_seq1, trans_seq2;

	/* Used to avoid infinite loops in case cache records point to each
	   others, causing a loop. FIXME: New cache files no longer support
	   overwriting existing data, so this could be removed and replaced
	   with a simple check that prev_offset is always smaller than the
	   current record's offset. */
	struct mail_cache_loop_track loop_track;
	/* Used for optimizing mail_cache_get_missing_reason() */
	struct mail_cache_missing_reason_cache reason_cache;

	/* if cached_exists_buf[field] == cached_exists_value, it's cached.
	   this allows us to avoid constantly clearing the whole buffer.
	   it needs to be cleared only when cached_exists_value is wrapped. */
	buffer_t *cached_exists_buf;
	uint8_t cached_exists_value;
	uint32_t cached_exists_seq;

	/* mail_cache_view_update_cache_decisions() has been used to disable
	   updating cache decisions. */
	bool no_decision_updates:1;
};

/* mail_cache_lookup_iter_next() returns the next found field. */
struct mail_cache_iterate_field {
	/* mail_cache_field.idx */
	unsigned int field_idx;
	/* Size of data */
	unsigned int size;
	/* Cache field content in the field type-specific format */
	const void *data;
	/* Offset to data in cache file */
	uoff_t offset;
};

struct mail_cache_lookup_iterate_ctx {
	struct mail_cache_view *view;
	/* This must match mail_cache.remap_counter or the iterator is
	   invalid. */
	unsigned int remap_counter;
	/* Message sequence as given to mail_cache_lookup_iter_init() */
	uint32_t seq;

	/* Pointer to current cache record being iterated. This may point
	   to the cache file or uncommitted transaction. */
	const struct mail_cache_record *rec;
	/* Iterator's current position in the cache record. Starts from
	   sizeof(mail_cache_record). */
	unsigned int pos;
	/* Copy of rec->size */
	unsigned int rec_size;
	/* Cache file offset to the beginning of rec, or 0 if it points to
	   an uncommitted transaction. */
	uint32_t offset;

	/* Used to loop through all changes in the uncommited transaction,
	   in case there are multiple changes to the same message. */
	unsigned int trans_next_idx;

	/* Cache has become unusable. Stop the iteration. */
	bool stop:1;
	/* I/O error or lock timeout occurred during iteration. Normally there
	   is no locking during iteration, but it may happen while cache is
	   being purged to wait for the purging to finish before cache can be
	   accessed again. */
	bool failed:1;
	/* Iteration has finished returning changes from uncommitted
	   transaction's in-memory buffer. */
	bool memory_appends_checked:1;
	/* Iteration has finished returning changes from uncommitted
	   transaction that were already written to cache file, but not
	   to main index. */
	bool disk_appends_checked:1;
	/* TRUE if the field index numbers in rec as the internal
	   mail_cache_field.idx (instead of the file-specific indexes).
	   This indicates that the rec points to uncommited transaction's
	   in-memory buffer. */
	bool inmemory_field_idx:1;
};

/* Explicitly lock the cache file. Returns -1 if error / timed out,
   1 if ok, 0 if cache is broken/doesn't exist */
int mail_cache_lock(struct mail_cache *cache);
/* Flush pending header updates and unlock. Returns -1 if cache is / just got
   corrupted, 0 if ok. */
int mail_cache_flush_and_unlock(struct mail_cache *cache);
/* Unlock the cache without any header updates. */
void mail_cache_unlock(struct mail_cache *cache);

int mail_cache_write(struct mail_cache *cache, const void *data, size_t size,
		     uoff_t offset);
int mail_cache_append(struct mail_cache *cache, const void *data, size_t size,
		      uint32_t *offset);

int mail_cache_header_fields_read(struct mail_cache *cache);
int mail_cache_header_fields_update(struct mail_cache *cache);
void mail_cache_header_fields_get(struct mail_cache *cache, buffer_t *dest);
int mail_cache_header_fields_get_next_offset(struct mail_cache *cache,
					     uint32_t *offset_r);
void mail_cache_expunge_count(struct mail_cache *cache, unsigned int count);

uint32_t mail_cache_lookup_cur_offset(struct mail_index_view *view,
				      uint32_t seq, uint32_t *reset_id_r);
int mail_cache_get_record(struct mail_cache *cache, uint32_t offset,
			  const struct mail_cache_record **rec_r);
uint32_t mail_cache_get_first_new_seq(struct mail_index_view *view);

/* Returns TRUE if offset..size area has been tracked before.
   Returns FALSE if the area may or may not have been tracked before,
   but we don't know for sure yet. */
bool mail_cache_track_loops(struct mail_cache_loop_track *loop_track,
			    uoff_t offset, uoff_t size);

/* Iterate through a message's cached fields. */
void mail_cache_lookup_iter_init(struct mail_cache_view *view, uint32_t seq,
				 struct mail_cache_lookup_iterate_ctx *ctx_r);
/* Returns 1 if field was returned, 0 if end of fields, or -1 if error.
   Note that this may trigger re-reading and reallocating cache fields. */
int mail_cache_lookup_iter_next(struct mail_cache_lookup_iterate_ctx *ctx,
				struct mail_cache_iterate_field *field_r);
const struct mail_cache_record *
mail_cache_transaction_lookup_rec(struct mail_cache_transaction_ctx *ctx,
				  unsigned int seq,
				  unsigned int *trans_next_idx);
bool mail_cache_transactions_have_changes(struct mail_cache *cache);

/* Return data from the specified position in the cache file. Returns 1 if
   successful, 0 if offset/size points outside the cache file, -1 if I/O
   error. */
int mail_cache_map(struct mail_cache *cache, size_t offset, size_t size,
		   const void **data_r);
/* Map the whole cache file into memory. Returns 1 if ok, 0 if corrupted
   (and deleted), -1 if I/O error. */
int mail_cache_map_all(struct mail_cache *cache);
void mail_cache_file_close(struct mail_cache *cache);
int mail_cache_reopen(struct mail_cache *cache);
int mail_cache_sync_reset_id(struct mail_cache *cache);

/* Notify the decision handling code that field was looked up for seq.
   This should be called even for fields that aren't currently in cache file.
   This is used to update caching decisions for fields that already exist
   in the cache file. */
void mail_cache_decision_state_update(struct mail_cache_view *view,
				      uint32_t seq, unsigned int field);
const char *mail_cache_decision_to_string(enum mail_cache_decision_type dec);
struct event_passthrough *
mail_cache_decision_changed_event(struct mail_cache *cache, struct event *event,
				  unsigned int field);

bool mail_cache_headers_check_capped(struct mail_cache *cache);

struct mail_cache_purge_drop_ctx {
	struct mail_cache *cache;
	time_t max_yes_downgrade_time;
	time_t max_temp_drop_time;
};
enum mail_cache_purge_drop_decision {
	MAIL_CACHE_PURGE_DROP_DECISION_NONE,
	MAIL_CACHE_PURGE_DROP_DECISION_DROP,
	MAIL_CACHE_PURGE_DROP_DECISION_TO_TEMP,
};
void mail_cache_purge_drop_init(struct mail_cache *cache,
				const struct mail_index_header *hdr,
				struct mail_cache_purge_drop_ctx *ctx_r);
enum mail_cache_purge_drop_decision
mail_cache_purge_drop_test(struct mail_cache_purge_drop_ctx *ctx,
			   unsigned int field);

int mail_cache_expunge_handler(struct mail_index_sync_map_ctx *sync_ctx,
			       const void *data, void **sync_context);

void mail_cache_set_syscall_error(struct mail_cache *cache,
				  const char *function) ATTR_COLD;

#endif
