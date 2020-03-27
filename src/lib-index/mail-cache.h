#ifndef MAIL_CACHE_H
#define MAIL_CACHE_H

#include "mail-index.h"

#define MAIL_CACHE_FILE_SUFFIX ".cache"

struct mail_cache;
struct mail_cache_view;
struct mail_cache_transaction_ctx;
struct mail_cache_compress_lock;

enum mail_cache_decision_type {
	/* Not needed currently */
	MAIL_CACHE_DECISION_NO		= 0x00,
	/* Needed only for new mails. Drop when compressing. */
	MAIL_CACHE_DECISION_TEMP	= 0x01,
	/* Needed. */
	MAIL_CACHE_DECISION_YES		= 0x02,

	/* This decision has been forced manually, don't change it. */
	MAIL_CACHE_DECISION_FORCED	= 0x80
};

enum mail_cache_field_type {
	MAIL_CACHE_FIELD_FIXED_SIZE,
	MAIL_CACHE_FIELD_VARIABLE_SIZE,
	MAIL_CACHE_FIELD_STRING,
	MAIL_CACHE_FIELD_BITMASK,
	MAIL_CACHE_FIELD_HEADER,

	MAIL_CACHE_FIELD_COUNT
};

struct mail_cache_field {
	const char *name;
	unsigned int idx;

	enum mail_cache_field_type type;
	unsigned int field_size;
	enum mail_cache_decision_type decision;
	/* If higher than the current last_used field, update it */
	time_t last_used;
};

struct mail_cache *mail_cache_open_or_create(struct mail_index *index);
struct mail_cache *
mail_cache_open_or_create_path(struct mail_index *index, const char *path);
void mail_cache_free(struct mail_cache **cache);

/* Register fields. fields[].idx is updated to contain field index.
   If field already exists and its caching decision is NO, the decision is
   updated to the input field's decision. */
void mail_cache_register_fields(struct mail_cache *cache,
				struct mail_cache_field *fields,
				unsigned int fields_count);
/* Returns registered field index, or UINT_MAX if not found. */
unsigned int
mail_cache_register_lookup(struct mail_cache *cache, const char *name);
/* Returns specified field */
const struct mail_cache_field *
mail_cache_register_get_field(struct mail_cache *cache, unsigned int field_idx);
/* Returns a list of all registered fields */
struct mail_cache_field *
mail_cache_register_get_list(struct mail_cache *cache, pool_t pool,
			     unsigned int *count_r);

/* Returns TRUE if cache should be compressed. */
bool mail_cache_need_compress(struct mail_cache *cache);
/* Compress cache file. Offsets are updated to given transaction. The cache
   compression lock should be kept until the transaction is committed.
   mail_cache_compress_unlock() needs to be called afterwards. The lock doesn't
   prevent updates to the cache while it's held, it only prevents another cache
   compression.

   The cache compression is done only if the current cache file's file_seq
   matches compress_file_seq. The idea is that compression isn't done if
   another process had just compressed it. 0 means the cache file is created
   only if it didn't already exist. (uint32_t)-1 means that compression is
   done always regardless of file_seq. */
int mail_cache_compress_with_trans(struct mail_cache *cache,
				   struct mail_index_transaction *trans,
				   uint32_t compress_file_seq,
				   struct mail_cache_compress_lock **lock_r);
int mail_cache_compress(struct mail_cache *cache, uint32_t compress_file_seq);
int mail_cache_compress_forced(struct mail_cache *cache,
			       struct mail_index_transaction *trans,
			       struct mail_cache_compress_lock **lock_r);
void mail_cache_compress_unlock(struct mail_cache_compress_lock **lock);
/* Returns TRUE if there is at least something in the cache. */
bool mail_cache_exists(struct mail_cache *cache);
/* Open and read cache header. Returns 0 if ok, -1 if error/corrupted. */
int mail_cache_open_and_verify(struct mail_cache *cache);

struct mail_cache_view *
mail_cache_view_open(struct mail_cache *cache, struct mail_index_view *iview);
void mail_cache_view_close(struct mail_cache_view **view);

/* Normally cache decisions are updated on lookup/add. Use this function to
   enable/disable this (useful for precaching data). */
void mail_cache_view_update_cache_decisions(struct mail_cache_view *view,
					    bool update);

/* Copy caching decisions. This is expected to be called only for a newly
   created empty mailbox. */
int mail_cache_decisions_copy(struct mail_cache *src, struct mail_cache *dst);

/* Get index transaction specific cache transaction. */
struct mail_cache_transaction_ctx *
mail_cache_get_transaction(struct mail_cache_view *view,
			   struct mail_index_transaction *t);

void mail_cache_transaction_reset(struct mail_cache_transaction_ctx *ctx);
int mail_cache_transaction_commit(struct mail_cache_transaction_ctx **ctx);
void mail_cache_transaction_rollback(struct mail_cache_transaction_ctx **ctx);

/* Add new field to given record. Updates are not allowed. Fixed size fields
   must be exactly the expected size. */
void mail_cache_add(struct mail_cache_transaction_ctx *ctx, uint32_t seq,
		    unsigned int field_idx, const void *data, size_t data_size);
/* Returns TRUE if field is wanted to be added and it doesn't already exist.
   If current caching decisions say not to cache this field, FALSE is returned.
   If seq is 0, the existence isn't checked. */
bool mail_cache_field_want_add(struct mail_cache_transaction_ctx *ctx,
			       uint32_t seq, unsigned int field_idx);
/* Like mail_cache_field_want_add(), but in caching decisions FALSE is
   returned only if the decision is a forced no. */
bool mail_cache_field_can_add(struct mail_cache_transaction_ctx *ctx,
			      uint32_t seq, unsigned int field_idx);
/* Notify cache that the mail is now closed. Any records added with
   mail_cache_add() are unlikely to be required again. This mainly tells
   INDEX=MEMORY that it can free up the memory used by the mail. */
void mail_cache_close_mail(struct mail_cache_transaction_ctx *ctx,
			   uint32_t seq);

/* Returns 1 if field exists, 0 if not, -1 if error. */
int mail_cache_field_exists(struct mail_cache_view *view, uint32_t seq,
			    unsigned int field_idx);
/* Returns TRUE if something is cached for the message, FALSE if not. */
bool mail_cache_field_exists_any(struct mail_cache_view *view, uint32_t seq);
/* Returns current caching decision for given field. */
enum mail_cache_decision_type
mail_cache_field_get_decision(struct mail_cache *cache, unsigned int field_idx);
/* Notify the decision handling code when field is committed to cache.
   If this is the first time the field is added to cache, its caching decision
   is updated to TEMP. */
void mail_cache_decision_add(struct mail_cache_view *view, uint32_t seq,
			     unsigned int field);

/* Set data_r and size_r to point to wanted field in cache file.
   Returns 1 if field was found, 0 if not, -1 if error. */
int mail_cache_lookup_field(struct mail_cache_view *view, buffer_t *dest_buf,
			    uint32_t seq, unsigned int field_idx);

/* Return specified cached headers. Returns 1 if all fields were found,
   0 if not, -1 if error. dest is updated only if all fields were found. */
int mail_cache_lookup_headers(struct mail_cache_view *view, string_t *dest,
			      uint32_t seq, const unsigned int field_idxs[],
			      unsigned int fields_count);

/* "Error in index cache file %s: ...". */
void mail_cache_set_corrupted(struct mail_cache *cache, const char *fmt, ...)
	ATTR_FORMAT(2, 3);
void mail_cache_set_seq_corrupted_reason(struct mail_cache_view *cache_view,
					 uint32_t seq, const char *reason);
/* Delete the cache file. */
void mail_cache_reset(struct mail_cache *cache);

/* Returns human-readable reason for why a cached field is missing for
   the specified mail. This is mainly for debugging purposes, so the exact
   field doesn't matter here. */
const char *
mail_cache_get_missing_reason(struct mail_cache_view *view, uint32_t seq);

#endif
