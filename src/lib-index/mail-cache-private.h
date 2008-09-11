#ifndef MAIL_CACHE_PRIVATE_H
#define MAIL_CACHE_PRIVATE_H

#include "file-dotlock.h"
#include "mail-index-private.h"
#include "mail-cache.h"

#define MAIL_CACHE_VERSION 1

/* Drop fields that haven't been accessed for n seconds */
#define MAIL_CACHE_FIELD_DROP_SECS (3600*24*30)

/* Never compress the file if it's smaller than this */
#define MAIL_CACHE_COMPRESS_MIN_SIZE (1024*50)

/* Don't bother remembering holes smaller than this */
#define MAIL_CACHE_MIN_HOLE_SIZE 1024

/* Compress the file when deleted space reaches n% of total size */
#define MAIL_CACHE_COMPRESS_PERCENTAGE 20

/* Compress the file when n% of rows contain continued rows.
   200% means that there's 2 continued rows per record. */
#define MAIL_CACHE_COMPRESS_CONTINUED_PERCENTAGE 200

/* Compress the file when we need to follow more than n next_offsets to find
   the latest cache header. */
#define MAIL_CACHE_HEADER_FIELD_CONTINUE_COUNT 4

/* Initial size for the file */
#define MAIL_CACHE_INITIAL_SIZE (sizeof(struct mail_cache_header) + 10240)

/* When more space is needed, grow the file n% larger than the previous size */
#define MAIL_CACHE_GROW_PERCENTAGE 10

/* When allocating space for transactions, don't use blocks larger than this. */
#define MAIL_CACHE_MAX_RESERVED_BLOCK_SIZE (1024*512)

#define MAIL_CACHE_LOCK_TIMEOUT 10
#define MAIL_CACHE_LOCK_CHANGE_TIMEOUT 300

#define CACHE_RECORD(cache, offset) \
	((const struct mail_cache_record *) \
	 ((const char *) (cache)->data + offset))

#define MAIL_CACHE_IS_UNUSABLE(cache) \
	((cache)->hdr == NULL)

struct mail_cache_header {
	/* version is increased only when you can't have backwards
	   compatibility. */
	uint8_t version;
	uint8_t compat_sizeof_uoff_t;
	uint8_t unused[2];

	uint32_t indexid;
	uint32_t file_seq;

	uint32_t continued_record_count;

	uint32_t hole_offset;
	uint32_t used_file_size;
	uint32_t deleted_space;

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

struct mail_cache_hole_header {
	uint32_t next_offset; /* 0 if no holes left */
	uint32_t size; /* including this header */

	/* make sure we notice if we're treating hole as mail_cache_record.
	   magic is a large number so if it's treated as size field, it'll
	   point outside the file */
#define MAIL_CACHE_HOLE_HEADER_MAGIC 0xffeedeff
	uint32_t magic;
};

struct mail_cache_field_private {
	struct mail_cache_field field;

	uint32_t uid_highwater;
	uint32_t last_used;

	/* Unused fields aren't written to cache file */
	unsigned int used:1;
	unsigned int adding:1;
	unsigned int decision_dirty:1;
};

struct mail_cache {
	struct mail_index *index;
	uint32_t ext_id;

	char *filepath;
	int fd;

	ino_t st_ino;
	dev_t st_dev;

	void *mmap_base;
	const void *data;
	size_t mmap_length;
	struct file_cache *file_cache;
	/* mail_cache_map() increases this always. */
	unsigned int remap_counter;

	struct dotlock_settings dotlock_settings;
	struct dotlock *dotlock;
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
	struct hash_table *field_name_hash; /* name -> idx */
	uint32_t last_field_header_offset;

	/* 0 is no need for compression, otherwise the file sequence number
	   which we want compressed. */
	uint32_t need_compress_file_seq;

	unsigned int *file_field_map;
	unsigned int file_fields_count;

	unsigned int opened:1;
	unsigned int locked:1;
	unsigned int last_lock_failed:1;
	unsigned int hdr_modified:1;
	unsigned int field_header_write_pending:1;
	unsigned int compressing:1;
};

struct mail_cache_loop_track {
	/* we're looping if size_sum > (max_offset-min_offset) */
	uoff_t min_offset, max_offset;
	uoff_t size_sum;
};

struct mail_cache_view {
	struct mail_cache *cache;
	struct mail_index_view *view, *trans_view;

	struct mail_cache_transaction_ctx *transaction;
	uint32_t trans_seq1, trans_seq2;

	struct mail_cache_loop_track loop_track;

	/* if cached_exists_buf[field] == cached_exists_value, it's cached.
	   this allows us to avoid constantly clearing the whole buffer.
	   it needs to be cleared only when cached_exists_value is wrapped. */
	buffer_t *cached_exists_buf;
	uint8_t cached_exists_value;
	uint32_t cached_exists_seq;
};

struct mail_cache_iterate_field {
	unsigned int field_idx;
	const void *data;
	unsigned int size;
};

struct mail_cache_lookup_iterate_ctx {
	struct mail_cache_view *view;
	unsigned int remap_counter;
	uint32_t seq;

	const struct mail_cache_record *rec;
	unsigned int pos, rec_size;
	uint32_t offset;

	unsigned int stop:1;
	unsigned int failed:1;
	unsigned int appends_checked:1;
};

int mail_cache_open_and_verify(struct mail_cache *cache);

/* Explicitly lock the cache file. Returns -1 if error / timed out,
   1 if ok, 0 if cache is broken/doesn't exist */
int mail_cache_lock(struct mail_cache *cache, bool require_same_reset_id);
int mail_cache_try_lock(struct mail_cache *cache);
/* Returns -1 if cache is / just got corrupted, 0 if ok. */
int mail_cache_unlock(struct mail_cache *cache);

int mail_cache_write(struct mail_cache *cache, const void *data, size_t size,
		     uoff_t offset);

int mail_cache_header_fields_read(struct mail_cache *cache);
int mail_cache_header_fields_update(struct mail_cache *cache);
void mail_cache_header_fields_get(struct mail_cache *cache, buffer_t *dest);
int mail_cache_header_fields_get_next_offset(struct mail_cache *cache,
					     uint32_t *offset_r);

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

int mail_cache_map(struct mail_cache *cache, size_t offset, size_t size);
void mail_cache_file_close(struct mail_cache *cache);
int mail_cache_reopen(struct mail_cache *cache);

/* Update new_offset's prev_offset field to old_offset. */
int mail_cache_link(struct mail_cache *cache, uint32_t old_offset,
		    uint32_t new_offset);
/* Mark record in given offset to be deleted. */
int mail_cache_delete(struct mail_cache *cache, uint32_t offset);

/* Notify the decision handling code that field was looked up for seq.
   This should be called even for fields that aren't currently in cache file */
void mail_cache_decision_state_update(struct mail_cache_view *view,
				      uint32_t seq, unsigned int field);
void mail_cache_decision_add(struct mail_cache_view *view, uint32_t seq,
			     unsigned int field);

int mail_cache_expunge_handler(struct mail_index_sync_map_ctx *sync_ctx,
			       uint32_t seq, const void *data,
			       void **sync_context, void *context);
int mail_cache_sync_handler(struct mail_index_sync_map_ctx *sync_ctx,
			    uint32_t seq, void *old_data, const void *new_data,
			    void **context);
void mail_cache_sync_lost_handler(struct mail_index *index);

void mail_cache_set_syscall_error(struct mail_cache *cache,
				  const char *function);

#endif
