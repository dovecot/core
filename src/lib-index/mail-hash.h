#ifndef MAIL_HASH_H
#define MAIL_HASH_H

#include "hash.h"

#define MAIL_HASH_VERSION 1

struct mail_hash;

/* File format:

   [header]
   [hash_size * (uint32_t idx)]
   [record_count * (struct mail_hash_record)]

   The indexes start from 1, so 0 means "doesn't exist".
*/

struct mail_hash_header {
	/* File format version */
	uint8_t version;
	/* Corrupted flag is set while file is being modified. */
	uint8_t corrupted;
	uint8_t unused[3];

	uint16_t base_header_size;
	/* Full size of each mail_hash_record */
	uint16_t record_size;
	/* Full header size. Currently always the same as base_header_size. */
	uint32_t header_size;
	/* Number of records after the hash table, includes holes */
	uint32_t record_count;
	/* Number of message records (records with non-zero UID) */
	uint32_t message_count;
	/* Number of messages with non-zero hash */
	uint32_t hashed_count;

	/* UID validity. */
	uint32_t uid_validity;
	/* The last UID which has been added to this file (but may have been
	   expunged already) */
	uint32_t last_uid;

	/* Holes is a linked list of unused records */
	uint32_t first_hole_idx;
	/* Hash size as a number of elements */
	uint32_t hash_size;
};

struct mail_hash_record {
	/* Linked list of records for hash collisions. */
	uint32_t next_idx;
	/* UID of the mail this record belongs to, or 0 if nothing.
	   (uint32_t)-1 means this record is deleted */
	uint32_t uid;
	/* user_data[] */
};
#define MAIL_HASH_RECORD_IS_DELETED(rec) \
	((rec)->uid == (uint32_t)-1)

enum mail_hash_open_flags {
	MAIL_HASH_OPEN_FLAG_CREATE	= 0x01,
	MAIL_HASH_OPEN_FLAG_IN_MEMORY	= 0x02
};

/* Returns 0 if the pointers are equal. */
typedef bool hash_ctx_cmp_callback_t(const void *key, const void *data,
				     void *context);
/* map[] contains old -> new index mapping. */
typedef int mail_hash_resize_callback_t(struct mail_hash *tmp_hash,
					uint32_t first_changed_idx,
					const uint32_t *map,
					unsigned int map_size, void *context);

struct mail_hash *
mail_hash_open(struct mail_index *index, const char *suffix,
	       enum mail_hash_open_flags flags, unsigned int record_size,
	       unsigned int initial_count,
	       hash_callback_t *key_hash_cb,
	       hash_callback_t *rec_hash_cb,
	       hash_ctx_cmp_callback_t *key_compare_cb,
	       void *context);
#ifdef CONTEXT_TYPE_SAFETY
#define mail_hash_open(index, suffix, flags, record_size, initial_count, \
		       key_hash_cb, rec_hash_cb, key_compare_cb, context) \
	({(void)(1 ? 0 : key_compare_cb((const void *)NULL, \
					(const void *)NULL, context)); \
	  mail_hash_open(index, suffix, flags, record_size, initial_count, \
		key_hash_cb, rec_hash_cb, \
		(hash_ctx_cmp_callback_t *)key_compare_cb, context); })
#else
#define mail_hash_open(index, suffix, flags, record_size, initial_count, \
		       key_hash_cb, rec_hash_cb, key_compare_cb, context) \
	  mail_hash_open(index, suffix, flags, record_size, initial_count, \
		key_hash_cb, rec_hash_cb, \
		(hash_ctx_cmp_callback_t *)key_compare_cb, context)
#endif
void mail_hash_free(struct mail_hash **hash);

/* If reset or resize fails, the hash file is closed and the hash is in
   unusable state until mail_hash_lock() succeeds. */
int mail_hash_reset(struct mail_hash *hash, unsigned int initial_count);
int mail_hash_resize_if_needed(struct mail_hash *hash, unsigned int grow_count,
			       mail_hash_resize_callback_t *callback,
			       void *context);

/* Lock hash file. Returns 1 if we locked the file, 0 if timeouted or hash
   is in memory, -1 if error. */
int mail_hash_lock(struct mail_hash *hash);
void mail_hash_unlock(struct mail_hash *hash);

const struct mail_hash_header *mail_hash_get_header(struct mail_hash *hash);

int mail_hash_lookup(struct mail_hash *hash, const void *key,
		     const void **value_r, uint32_t *idx_r);
/* Remember that inserting may cause existing returned values to be
   invalidated. If key=NULL, it's not inserted into hash table. Note that
   hash=0 equals to key=NULL insert, so a valid hash value must never be 0. */
int mail_hash_insert(struct mail_hash *hash, const void *key,
		     const void *value, uint32_t *idx_r);
int mail_hash_remove(struct mail_hash *hash, const void *key);

unsigned int mail_hash_value_idx(struct mail_hash *hash, const void *value);
int mail_hash_lookup_idx(struct mail_hash *hash, uint32_t idx,
			 const void **value_r);
int mail_hash_update_idx(struct mail_hash *hash, uint32_t idx,
			 const void *value);
int mail_hash_remove_idx(struct mail_hash *hash, uint32_t idx, const void *key);

void mail_hash_set_corrupted(struct mail_hash *hash, const char *error);

#endif
