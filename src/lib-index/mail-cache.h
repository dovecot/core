#ifndef __MAIL_CACHE_H
#define __MAIL_CACHE_H

#include "mail-index.h"

#define MAIL_CACHE_FILE_PREFIX ".cache"

#define MAIL_CACHE_HEADERS_COUNT 4

struct mail_cache;
struct mail_cache_view;
struct mail_cache_transaction_ctx;

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

enum mail_cache_record_flag {
	/* If binary flags are set, it's not checked whether mail is
	   missing CRs. So this flag may be set as an optimization for
	   regular non-binary mails as well if it's known that it contains
	   valid CR+LF line breaks. */
	MAIL_INDEX_FLAG_BINARY_HEADER		= 0x0001,
	MAIL_INDEX_FLAG_BINARY_BODY		= 0x0002,

	/* Mail header or body is known to contain NUL characters. */
	MAIL_INDEX_FLAG_HAS_NULS		= 0x0004,
	/* Mail header or body is known to not contain NUL characters. */
	MAIL_INDEX_FLAG_HAS_NO_NULS		= 0x0008
};

/* when modifying, remember to update mail_cache_field_sizes[] too */
enum mail_cache_field {
	/* fixed size fields */
	MAIL_CACHE_INDEX_FLAGS = 0,
	MAIL_CACHE_SENT_DATE,
	MAIL_CACHE_RECEIVED_DATE,
	MAIL_CACHE_VIRTUAL_FULL_SIZE,

	/* variable sized field */
	MAIL_CACHE_HEADERS1,
	MAIL_CACHE_HEADERS2,
	MAIL_CACHE_HEADERS3,
	MAIL_CACHE_HEADERS4,
	MAIL_CACHE_BODY,
	MAIL_CACHE_BODYSTRUCTURE,
	MAIL_CACHE_ENVELOPE,
	MAIL_CACHE_MESSAGEPART,
	MAIL_CACHE_UID_STRING,

	MAIL_CACHE_FIELD_COUNT
};

struct mail_sent_date {
	time_t time;
	int32_t timezone;
};

extern enum mail_cache_field mail_cache_header_fields[MAIL_CACHE_HEADERS_COUNT];

struct mail_cache *mail_cache_open_or_create(struct mail_index *index);
void mail_cache_free(struct mail_cache *cache);

void mail_cache_set_defaults(struct mail_cache *cache,
			     const enum mail_cache_decision_type dec[32]);

/* Returns TRUE if cache should be compressed. */
int mail_cache_need_compress(struct mail_cache *cache);
/* Compress cache file. */
int mail_cache_compress(struct mail_cache *cache, struct mail_index_view *view);

struct mail_cache_view *
mail_cache_view_open(struct mail_cache *cache, struct mail_index_view *iview);
void mail_cache_view_close(struct mail_cache_view *view);

/* Get index transaction specific cache transaction. */
struct mail_cache_transaction_ctx *
mail_cache_get_transaction(struct mail_cache_view *view,
			   struct mail_index_transaction *t);

/* Return NULL-terminated list of headers for given index, or NULL if
   header index isn't used. */
const char *const *mail_cache_get_header_fields(struct mail_cache_view *view,
						unsigned int idx);
/* Set list of headers for given index. */
int mail_cache_set_header_fields(struct mail_cache_transaction_ctx *ctx,
				 unsigned int idx, const char *const headers[]);

/* Add new field to given record. Updates are not allowed. Fixed size fields
   must be exactly the expected size. */
void mail_cache_add(struct mail_cache_transaction_ctx *ctx, uint32_t seq,
		    enum mail_cache_field field,
		    const void *data, size_t data_size);

/* Retursn TRUE if field exists. */
int mail_cache_field_exists(struct mail_cache_view *view, uint32_t seq,
			    enum mail_cache_field field);
/* Returns current caching decision for given field. */
enum mail_cache_decision_type
mail_cache_field_get_decision(struct mail_cache *cache,
			      enum mail_cache_field field);

/* Set data_r and size_r to point to wanted field in cache file.
   Returns TRUE if field was found. If field contains multiple fields,
   first one found is returned. This is mostly useful for finding headers. */
int mail_cache_lookup_field(struct mail_cache_view *view, buffer_t *dest_buf,
			    uint32_t seq, enum mail_cache_field field);

/* Return string field. */
int mail_cache_lookup_string_field(struct mail_cache_view *view, string_t *dest,
				   uint32_t seq, enum mail_cache_field field);

/* Return record flags. */
enum mail_cache_record_flag
mail_cache_get_record_flags(struct mail_cache_view *view, uint32_t seq);

/* Update record flags. The cache file must be locked and the flags must be
   already inserted to the record. */
int mail_cache_update_record_flags(struct mail_cache_view *view, uint32_t seq,
				   enum mail_cache_record_flag flags);

/* "Error in index cache file %s: ...". */
void mail_cache_set_corrupted(struct mail_cache *cache, const char *fmt, ...)
	__attr_format__(2, 3);

#endif
