#ifndef __MAIL_HASH_H
#define __MAIL_HASH_H

#include "hash.h"

#define MAIL_HASH_VERSION 1

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

/* Returns hash code. */
typedef unsigned int hash_ctx_callback_t(const void *p, void *context);
/* Returns 0 if the pointers are equal. */
typedef bool hash_ctx_cmp_callback_t(const void *key, const void *data,
				     void *context);

struct mail_hash *
mail_hash_open_or_create(struct mail_index *index, const char *suffix,
			 unsigned int record_size, hash_callback_t *hash_cb,
			 hash_ctx_cmp_callback_t *key_compare_cb,
			 void *context, bool in_memory);
void mail_hash_free(struct mail_hash **hash);

int mail_hash_reset(struct mail_hash *hash);

/* Lock hash file. Returns 1 if we locked the file, 0 if timeouted or hash
   is in memory, -1 if error. */
int mail_hash_lock(struct mail_hash *hash);
void mail_hash_unlock(struct mail_hash *hash);

const struct mail_hash_header *mail_hash_get_header(struct mail_hash *hash);

int mail_hash_lookup(struct mail_hash *hash, const void *key,
		     const void **value_r, uint32_t *idx_r);
/* Remember that inserting may cause existing returned values to be
   invalidated */
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
