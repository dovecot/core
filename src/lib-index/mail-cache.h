#ifndef __MAIL_CACHE_H
#define __MAIL_CACHE_H

#include "mail-index.h"

#define MAIL_CACHE_FILE_PREFIX ".cache"

#define MAIL_CACHE_HEADERS_COUNT 4

struct mail_cache_transaction_ctx;

enum mail_cache_field {
	/* fixed size fields */
	MAIL_CACHE_INDEX_FLAGS		= 0x00000001,
	MAIL_CACHE_LOCATION_OFFSET	= 0x00000002,
	MAIL_CACHE_MD5			= 0x00000004,
	MAIL_CACHE_SENT_DATE		= 0x00000008,
	MAIL_CACHE_RECEIVED_DATE	= 0x00000010,
	MAIL_CACHE_VIRTUAL_FULL_SIZE	= 0x00000020,

	/* variable sized field */
	MAIL_CACHE_HEADERS1		= 0x40000000,
	MAIL_CACHE_HEADERS2		= 0x20000000,
	MAIL_CACHE_HEADERS3		= 0x10000000,
	MAIL_CACHE_HEADERS4		= 0x08000000,
	MAIL_CACHE_LOCATION		= 0x04000000,
	MAIL_CACHE_BODY			= 0x02000000,
	MAIL_CACHE_BODYSTRUCTURE	= 0x01000000,
	MAIL_CACHE_ENVELOPE		= 0x00800000,
	MAIL_CACHE_MESSAGEPART		= 0x00400000,

	MAIL_CACHE_FIXED_MASK		= MAIL_CACHE_INDEX_FLAGS |
					  MAIL_CACHE_LOCATION_OFFSET |
					  MAIL_CACHE_MD5 |
					  MAIL_CACHE_SENT_DATE |
					  MAIL_CACHE_RECEIVED_DATE |
					  MAIL_CACHE_VIRTUAL_FULL_SIZE,
	MAIL_CACHE_HEADERS_MASK		= MAIL_CACHE_HEADERS1 |
					  MAIL_CACHE_HEADERS2 |
					  MAIL_CACHE_HEADERS3 |
					  MAIL_CACHE_HEADERS4,
	MAIL_CACHE_STRING_MASK		= MAIL_CACHE_HEADERS_MASK |
					  MAIL_CACHE_LOCATION |
					  MAIL_CACHE_BODY |
					  MAIL_CACHE_BODYSTRUCTURE |
					  MAIL_CACHE_ENVELOPE,
	MAIL_CACHE_BODYSTRUCTURE_MASK	= MAIL_CACHE_BODY |
					  MAIL_CACHE_BODYSTRUCTURE |
                                          MAIL_CACHE_MESSAGEPART
};

struct mail_sent_date {
	time_t time;
	int timezone;
};

extern enum mail_cache_field mail_cache_header_fields[MAIL_CACHE_HEADERS_COUNT];

int mail_cache_open_or_create(struct mail_index *index);
void mail_cache_free(struct mail_cache *cache);

void mail_cache_set_defaults(struct mail_cache *cache,
			     enum mail_cache_field default_cache_fields,
			     enum mail_cache_field never_cache_fields);

/* Compress cache file. */
int mail_cache_compress(struct mail_cache *cache);

/* Truncate the cache file and update it's indexid */
int mail_cache_truncate(struct mail_cache *cache);

/* Set indexid to 0 to notify other processes using this file that they should
   re-open it. */
int mail_cache_mark_file_deleted(struct mail_cache *cache);

/* Explicitly lock the cache file. Returns 1 if ok, 0 if nonblock is TRUE and
   we couldn't immediately get a lock, or -1 if error. */
int mail_cache_lock(struct mail_cache *cache, int nonblock);
int mail_cache_unlock(struct mail_cache *cache);

/* Mark the lock to be removed when unlocking index file. */
void mail_cache_unlock_later(struct mail_cache *cache);

/* Returns TRUE if cache file is locked. */
int mail_cache_is_locked(struct mail_cache *cache);

/* Begin transaction. Returns same as mail_cache_lock(). Note that if you
   call lookup functions for messages within first and last message in
   transaction, the transaction will be automatically committed. */
int mail_cache_transaction_begin(struct mail_cache *cache, int nonblock,
				 struct mail_cache_transaction_ctx **ctx_r);
/* End transaction. Single transaction can have multiple commits/rollbacks.
   If there's any pending changes, they will be rolled back. */
int mail_cache_transaction_end(struct mail_cache_transaction_ctx *ctx);

int mail_cache_transaction_commit(struct mail_cache_transaction_ctx *ctx);
int mail_cache_transaction_rollback(struct mail_cache_transaction_ctx *ctx);

/* Return NULL-terminated list of headers for given index, or NULL if
   header index isn't used. */
const char *const *mail_cache_get_header_fields(struct mail_cache *cache,
						unsigned int idx);
/* Set list of headers for given index. */
int mail_cache_set_header_fields(struct mail_cache_transaction_ctx *ctx,
				 unsigned int idx, const char *const headers[]);

/* Add new field to given record. Updates are not allowed. Fixed size fields
   must be exactly the expected size and they're converted to network byte
   order in disk. */
int mail_cache_add(struct mail_cache_transaction_ctx *ctx,
		   struct mail_index_record *rec, enum mail_cache_field field,
		   const void *data, size_t data_size);

/* Mark the given record deleted. */
int mail_cache_delete(struct mail_cache_transaction_ctx *ctx,
		      struct mail_index_record *rec);

/* Return all fields that are currently cached for record. */
enum mail_cache_field
mail_cache_get_fields(struct mail_cache *cache,
		      const struct mail_index_record *rec);

/* Set data_r and size_r to point to wanted field in cache file.
   Returns TRUE if field was found. If field contains multiple fields,
   first one found is returned. This is mostly useful for finding headers. */
int mail_cache_lookup_field(struct mail_cache *cache,
			    const struct mail_index_record *rec,
			    enum mail_cache_field field,
			    const void **data_r, size_t *size_r);

/* Return string field. */
const char *mail_cache_lookup_string_field(struct mail_cache *cache,
					   const struct mail_index_record *rec,
					   enum mail_cache_field field);


/* Copy fixed size field to given buffer. buffer_size must be exactly the
   expected size. The result will be converted to host byte order.
   Returns TRUE if field was found. */
int mail_cache_copy_fixed_field(struct mail_cache *cache,
				const struct mail_index_record *rec,
				enum mail_cache_field field,
				void *buffer, size_t buffer_size);

/* Mark given fields as missing, ie. they should be cached when possible. */
void mail_cache_mark_missing(struct mail_cache *cache,
			     enum mail_cache_field fields);

/* Return index flags. */
enum mail_index_record_flag
mail_cache_get_index_flags(struct mail_cache *cache,
			   const struct mail_index_record *rec);

/* Update index flags. The cache file must be locked and the flags must be
   already inserted to the record. */
int mail_cache_update_index_flags(struct mail_cache *cache,
				  struct mail_index_record *rec,
				  enum mail_index_record_flag flags);

/* Return the whole file mmaped. */
void *mail_cache_get_mmaped(struct mail_cache *cache, size_t *size);

/* "Error in index cache file %s: ...". */
int mail_cache_set_corrupted(struct mail_cache *cache, const char *fmt, ...)
	__attr_format__(2, 3);

#endif
