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
	/* version is increased only when you can't have backwards
	   compatibility. */
	uint8_t major_version;
	uint8_t compat_sizeof_uoff_t;
	uint8_t minor_version;
	uint8_t unused;

	uint32_t indexid;
	uint32_t file_seq;

	uint32_t continued_record_count;

	/* NOTE: old versions used this for hole offset, so we can't fully
	   rely on it */
	uint32_t record_count;
	uint32_t backwards_compat_used_file_size;
	uint32_t deleted_record_count;

	uint32_t field_header_offset;
};

struct mail_cache_header_fields {
	uint32_t next_offset;
	uint32_t size;
	uint32_t fields_count;

#if 0
	/* last time the field was accessed. not updated more often than
	   once a day. */
	uint32_t last_used[fields_count];
	/* (uint32_t)-1 for variable sized fields */
	uint32_t size[fields_count];
	/* enum mail_cache_field_type */
	uint8_t type[fields_count];
	/* enum mail_cache_decision_type */
	uint8_t decision[fields_count];
	/* NUL-separated list of field names */
	char name[fields_count][];
#endif
};

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

	uint32_t uid_highwater;

	/* Unused fields aren't written to cache file */
	bool used:1;
	bool decision_dirty:1;
};

struct mail_cache {
	struct mail_index *index;
	uint32_t ext_id;

	char *filepath;
	int fd;

	ino_t st_ino;
	dev_t st_dev;

	time_t last_mmap_error_time;

	uoff_t last_stat_size;
	size_t mmap_length;
	/* a) mmaping the whole file */
	void *mmap_base;
	/* b) using file cache */
	struct file_cache *file_cache;
	/* c) using small read() calls with MAIL_INDEX_OPEN_FLAG_SAVEONLY */
	uoff_t read_offset;
	buffer_t *read_buf;
	/* mail_cache_map() increases this always. */
	unsigned int remap_counter;

	struct mail_cache_view *views;

	struct dotlock_settings dotlock_settings;
	struct file_lock *file_lock;

	/* mmap_disable=no: hdr points to data / NULL when cache is invalid.
	   mmap_disable=yes: hdr points to hdr_ro_copy. this is needed because
	   cache invalidation can zero the data any time */
	const struct mail_cache_header *hdr;
	struct mail_cache_header hdr_ro_copy;
	/* hdr_copy gets updated when cache is locked and written when
	   unlocking and hdr_modified=TRUE */
	struct mail_cache_header hdr_copy;

	pool_t field_pool;
	struct mail_cache_field_private *fields;
	uint32_t *field_file_map;
	unsigned int fields_count;
	HASH_TABLE(char *, void *) field_name_hash; /* name -> idx */
	uint32_t last_field_header_offset;

	/* 0 is no need for compression, otherwise the file sequence number
	   which we want compressed. */
	uint32_t need_compress_file_seq;

	unsigned int *file_field_map;
	unsigned int file_fields_count;

	bool opened:1;
	bool locked:1;
	bool last_lock_failed:1;
	bool hdr_modified:1;
	bool field_header_write_pending:1;
	bool compressing:1;
	bool map_with_read:1;
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
	uint32_t trans_seq1, trans_seq2;

	struct mail_cache_loop_track loop_track;
	struct mail_cache_missing_reason_cache reason_cache;

	/* if cached_exists_buf[field] == cached_exists_value, it's cached.
	   this allows us to avoid constantly clearing the whole buffer.
	   it needs to be cleared only when cached_exists_value is wrapped. */
	buffer_t *cached_exists_buf;
	uint8_t cached_exists_value;
	uint32_t cached_exists_seq;

	bool no_decision_updates:1;
};

struct mail_cache_iterate_field {
	unsigned int field_idx;
	unsigned int size;
	const void *data;
	uoff_t offset;
};

struct mail_cache_lookup_iterate_ctx {
	struct mail_cache_view *view;
	unsigned int remap_counter;
	uint32_t seq;

	const struct mail_cache_record *rec;
	unsigned int pos, rec_size;
	uint32_t offset;

	unsigned int trans_next_idx;

	bool stop:1;
	bool failed:1;
	bool memory_appends_checked:1;
	bool disk_appends_checked:1;
};

/* Explicitly lock the cache file. Returns -1 if error / timed out,
   1 if ok, 0 if cache is broken/doesn't exist */
int mail_cache_lock(struct mail_cache *cache);
int mail_cache_try_lock(struct mail_cache *cache);
/* Returns -1 if cache is / just got corrupted, 0 if ok. */
int mail_cache_unlock(struct mail_cache *cache);

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
/* Returns 1 if field was returned, 0 if end of fields, or -1 if error */
int mail_cache_lookup_iter_next(struct mail_cache_lookup_iterate_ctx *ctx,
				struct mail_cache_iterate_field *field_r);
const struct mail_cache_record *
mail_cache_transaction_lookup_rec(struct mail_cache_transaction_ctx *ctx,
				  unsigned int seq,
				  unsigned int *trans_next_idx);

/* Return data from the specified position in the cache file. Returns 1 if
   successful, 0 if offset/size points outside the cache file, -1 if error. */
int mail_cache_map(struct mail_cache *cache, size_t offset, size_t size,
		   const void **data_r);
/* Map the whole cache file into memory. Returns 0 if ok, -1 if error. */
int mail_cache_map_all(struct mail_cache *cache);
void mail_cache_file_close(struct mail_cache *cache);
int mail_cache_reopen(struct mail_cache *cache);

/* Notify the decision handling code that field was looked up for seq.
   This should be called even for fields that aren't currently in cache file.
   This is used to update caching decisions for fields that already exist
   in the cache file. */
void mail_cache_decision_state_update(struct mail_cache_view *view,
				      uint32_t seq, unsigned int field);

int mail_cache_expunge_handler(struct mail_index_sync_map_ctx *sync_ctx,
			       uint32_t seq, const void *data,
			       void **sync_context, void *context);

void mail_cache_set_syscall_error(struct mail_cache *cache,
				  const char *function);

#endif
