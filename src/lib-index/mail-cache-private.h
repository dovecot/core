#ifndef __MAIL_CACHE_PRIVATE_H
#define __MAIL_CACHE_PRIVATE_H

#include "mail-index-private.h"
#include "mail-cache.h"

#define MAIL_CACHE_VERSION 1

/* Never compress the file if it's smaller than this */
#define COMPRESS_MIN_SIZE (1024*50)

/* Don't bother remembering holes smaller than this */
#define MAIL_CACHE_MIN_HOLE_SIZE 1024

/* Compress the file when deleted space reaches n% of total size */
#define COMPRESS_PERCENTAGE 20

/* Compress the file when n% of rows contain continued rows.
   200% means that there's 2 continued rows per record. */
#define COMPRESS_CONTINUED_PERCENTAGE 200

/* Initial size for the file */
#define MAIL_CACHE_INITIAL_SIZE (sizeof(struct mail_cache_header) + 10240)

/* When more space is needed, grow the file n% larger than the previous size */
#define MAIL_CACHE_GROW_PERCENTAGE 10

#define MAIL_CACHE_LOCK_TIMEOUT 120
#define MAIL_CACHE_LOCK_CHANGE_TIMEOUT 60
#define MAIL_CACHE_LOCK_IMMEDIATE_TIMEOUT (5*60)

#define CACHE_RECORD(cache, offset) \
	((struct mail_cache_record *) ((char *) (cache)->mmap_base + offset))

#define MAIL_CACHE_IS_UNUSABLE(cache) \
	((cache)->hdr == NULL)

struct mail_cache_header {
	/* version is increased only when you can't have backwards
	   compatibility. */
	uint8_t version;
	uint8_t unused[3];

	uint32_t indexid;
	uint32_t file_seq;

	uint32_t continued_record_count;

	uint32_t hole_offset;
	uint32_t used_file_size;
	uint32_t deleted_space;

	uint32_t field_usage_last_used[32]; /* time_t */
	uint8_t field_usage_decision_type[32];

	uint32_t header_offsets[MAIL_CACHE_HEADERS_COUNT];
};

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

struct mail_cache {
	struct mail_index *index;

	char *filepath;
	int fd;

	void *mmap_base;
	size_t mmap_length;

	const struct mail_cache_header *hdr;
	struct mail_cache_header hdr_copy;

	pool_t split_header_pool;
	uint32_t split_offsets[MAIL_CACHE_HEADERS_COUNT];
	const char *const *split_headers[MAIL_CACHE_HEADERS_COUNT];

	uint8_t default_field_usage_decision_type[32];
	uint32_t field_usage_uid_highwater[32];

	unsigned int locked:1;
	unsigned int need_compress:1;
	unsigned int hdr_modified:1;
};

struct mail_cache_view {
	struct mail_cache *cache;
	struct mail_index_view *view;

	struct mail_cache_transaction_ctx *transaction;
	uint32_t trans_seq1, trans_seq2;

	char cached_exists[32];
	uint32_t cached_exists_seq;
};

typedef int mail_cache_foreach_callback_t(struct mail_cache_view *view,
					  enum mail_cache_field field,
					  const void *data, size_t data_size,
					  void *context);

extern unsigned int mail_cache_field_sizes[32];
extern enum mail_cache_field mail_cache_header_fields[MAIL_CACHE_HEADERS_COUNT];

uint32_t mail_cache_uint32_to_offset(uint32_t offset);
uint32_t mail_cache_offset_to_uint32(uint32_t offset);

/* Explicitly lock the cache file. Returns -1 if error, 1 if ok, 0 if we
   couldn't lock */
int mail_cache_lock(struct mail_cache *cache);
void mail_cache_unlock(struct mail_cache *cache);

const char *
mail_cache_get_header_fields_str(struct mail_cache *cache, unsigned int idx);
const char *const *
mail_cache_split_header(struct mail_cache *cache, const char *header);

struct mail_cache_record *
mail_cache_get_record(struct mail_cache *cache, uint32_t offset);

int mail_cache_foreach(struct mail_cache_view *view, uint32_t seq,
		       mail_cache_foreach_callback_t *callback, void *context);

int mail_cache_transaction_commit(struct mail_cache_transaction_ctx *ctx);
void mail_cache_transaction_rollback(struct mail_cache_transaction_ctx *ctx);

int mail_cache_transaction_lookup(struct mail_cache_transaction_ctx *ctx,
				  uint32_t seq, uint32_t *offset_r);

int mail_cache_map(struct mail_cache *cache, size_t offset, size_t size);
void mail_cache_file_close(struct mail_cache *cache);
int mail_cache_reopen(struct mail_cache *cache);

/* Update new_offset's prev_offset field to old_offset. */
int mail_cache_link(struct mail_cache *cache, uint32_t old_offset,
		    uint32_t new_offset);
/* Mark record in given offset to be deleted. */
int mail_cache_delete(struct mail_cache *cache, uint32_t offset);

void mail_cache_decision_lookup(struct mail_cache_view *view, uint32_t seq,
				enum mail_cache_field field);
void mail_cache_decision_add(struct mail_cache_view *view, uint32_t seq,
			     enum mail_cache_field field);

void mail_cache_set_syscall_error(struct mail_cache *cache,
				  const char *function);

#endif
