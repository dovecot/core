#ifndef __MAIL_CACHE_PRIVATE_H
#define __MAIL_CACHE_PRIVATE_H

#include "mail-index-private.h"
#include "mail-cache.h"

/* Never compress the file if it's smaller than this */
#define COMPRESS_MIN_SIZE (1024*50)

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

struct mail_cache_header {
	uint32_t indexid;
	uint32_t file_seq;

	uint32_t continued_record_count;

	uint32_t used_file_size;
	uint32_t deleted_space;

	uint32_t used_fields; /* enum mail_cache_field */

	uint32_t field_usage_start; /* time_t */
	uint32_t field_usage_counts[32];

	uint32_t header_offsets[MAIL_CACHE_HEADERS_COUNT];
};

struct mail_cache_record {
	uint32_t fields; /* enum mail_cache_field */
	uint32_t next_offset;
	uint32_t size; /* full record size, including this header */
};

struct mail_cache {
	struct mail_index *index;

	char *filepath;
	int fd;

	void *mmap_base;
	size_t mmap_length;
	uint32_t used_file_size;

	struct mail_cache_header *hdr;

	pool_t split_header_pool;
	uint32_t split_offsets[MAIL_CACHE_HEADERS_COUNT];
	const char *const *split_headers[MAIL_CACHE_HEADERS_COUNT];

	enum mail_cache_field default_cache_fields;
	enum mail_cache_field never_cache_fields;

        struct mail_cache_transaction_ctx *trans_ctx;
	unsigned int locks;

	unsigned int mmap_refresh:1;
	unsigned int silent:1;
};

struct mail_cache_view {
	struct mail_cache *cache;
	struct mail_index_view *view;

	unsigned int broken:1;
};

extern unsigned int mail_cache_field_sizes[32];
extern enum mail_cache_field mail_cache_header_fields[MAIL_CACHE_HEADERS_COUNT];

uint32_t mail_cache_uint32_to_offset(uint32_t offset);
uint32_t mail_cache_offset_to_uint32(uint32_t offset);

const char *
mail_cache_get_header_fields_str(struct mail_cache *cache, unsigned int idx);
const char *const *
mail_cache_split_header(struct mail_cache *cache, const char *header);

struct mail_cache_record *
mail_cache_get_record(struct mail_cache *cache, uint32_t offset);
struct mail_cache_record *
mail_cache_get_next_record(struct mail_cache *cache,
			   struct mail_cache_record *rec);

struct mail_cache_record *
mail_cache_lookup(struct mail_cache_view *view, uint32_t seq,
		  enum mail_cache_field fields);

int
mail_cache_transaction_autocommit(struct mail_cache_view *view,
				  uint32_t seq, enum mail_cache_field fields);

void mail_cache_set_syscall_error(struct mail_cache *cache,
				  const char *function);

#endif
