#ifndef MAIL_HASH_H
#define MAIL_HASH_H

#include "hash.h"

#define MAIL_HASH_VERSION 1

struct mail_index;
struct mail_hash;
struct mail_hash_transaction;

/* File format:

   [header]
   [hash_size * (uint32_t idx)]
   [record_count * hdr.record_size]

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
	/* Number of records after the hash table, includes [0] and holes */
	uint32_t record_count;
	/* Number of messages with non-zero hash */
	uint32_t hashed_count;

	/* Holes is a linked list of unused records. 0 = no holes. */
	uint32_t first_hole_idx;
	/* Hash size as number of elements */
	uint32_t hash_size;

	/* UID validity. */
	uint32_t uid_validity;
	/* The last UID which has been added to this file (but may have been
	   expunged already) */
	uint32_t last_uid;
	/* Number of message records (records with non-zero UID) */
	uint32_t message_count;
	/* Increased every time the hash is reset */
	uint32_t reset_counter;
};

struct mail_hash_record {
	/* Linked list of records for hash collisions.
	   (uint32_t)-1 means this record is deleted */
	uint32_t next_idx;
	/* user_data[] */
};
ARRAY_DEFINE_TYPE(mail_hash_record, struct mail_hash_record);
#define MAIL_HASH_RECORD_IS_DELETED(rec) \
	((rec)->next_idx == (uint32_t)-1)

enum mail_hash_lock_flags {
	MAIL_HASH_LOCK_FLAG_TRY			= 0x01,
	MAIL_HASH_LOCK_FLAG_CREATE_MISSING	= 0x02
};

/* Returns 0 if the pointers are equal. */
typedef bool mail_hash_ctx_cmp_callback_t(struct mail_hash_transaction *trans,
					  const void *key, uint32_t idx,
					  void *context);
/* map[] contains old -> new index mapping. */
typedef int mail_hash_remap_callback_t(struct mail_hash_transaction *trans,
				       const uint32_t *map,
				       unsigned int map_size, void *context);

/* suffix=NULL keeps the has only in memory */
struct mail_hash *
mail_hash_alloc(struct mail_index *index, const char *suffix,
		unsigned int record_size,
		hash_callback_t *key_hash_cb,
		hash_callback_t *rec_hash_cb,
		mail_hash_ctx_cmp_callback_t *key_compare_cb,
		mail_hash_remap_callback_t *remap_callback,
		void *context);
void mail_hash_free(struct mail_hash **hash);

/* Returns 1 if created and locked, 0 if already exists, -1 if error. */
int mail_hash_create_excl_locked(struct mail_hash *hash);

/* Lock the file. Returns 1 if locking was successful, 0 if file doesn't exist,
   -1 if error. */
int mail_hash_lock_shared(struct mail_hash *hash);
/* If FLAG_TRY_LOCK is set and file is already locked, return 0.
   Otherwise return values are identical with mail_hash_lock_shared() */
int mail_hash_lock_exclusive(struct mail_hash *hash,
			     enum mail_hash_lock_flags flags);
void mail_hash_unlock(struct mail_hash *hash);
/* Returns the current locking state (F_UNLCK, F_RDLCK, F_WRLCK) */
int mail_hash_get_lock_type(struct mail_hash *hash);

struct mail_hash_transaction *
mail_hash_transaction_begin(struct mail_hash *hash, unsigned int min_hash_size);
int mail_hash_transaction_write(struct mail_hash_transaction *trans);
void mail_hash_transaction_end(struct mail_hash_transaction **trans);
/* Returns TRUE if transaction is in broken state because of an earlier
   I/O error or detected file corruption. */
bool mail_hash_transaction_is_broken(struct mail_hash_transaction *trans);
/* Returns TRUE if hash is currently being updated in memory. */
bool mail_hash_transaction_is_in_memory(struct mail_hash_transaction *trans);

/* Returns the hash structure of the transaction. */
struct mail_hash *
mail_hash_transaction_get_hash(struct mail_hash_transaction *trans);

/* Clear the entire hash file's contents. */
void mail_hash_reset(struct mail_hash_transaction *trans);
/* Read the entire file to memory. */
int mail_hash_map_file(struct mail_hash_transaction *trans);

/* Returns a modifiable hash header. */
struct mail_hash_header *
mail_hash_get_header(struct mail_hash_transaction *trans);

/* Look up key from hash and return its value or NULL if key isn't in the hash.
   NULL is also returned if the lookup fails because of I/O error or file
   corruption. */
void *mail_hash_lookup(struct mail_hash_transaction *trans, const void *key,
		       uint32_t *idx_r);
/* Never returns NULL. If the lookup fails the transaction is marked broken
   and a pointer to a dummy record is returned. */
void *mail_hash_lookup_idx(struct mail_hash_transaction *trans, uint32_t idx);

/* If key=NULL, it's only added as a record after the hash table and not
   added to the actual hash table. Note that hash=0 equals to key=NULL insert,
   so a valid hash value must never be 0. */
void mail_hash_insert(struct mail_hash_transaction *trans, const void *key,
		      const void *value, uint32_t *idx_r);
/* Mark the record at given index as modified. */
void mail_hash_update(struct mail_hash_transaction *trans, uint32_t idx);
/* idx must be provided. key_hash must be provided if the record was added
   with non-NULL key. */
void mail_hash_remove(struct mail_hash_transaction *trans,
		      uint32_t idx, uint32_t key_hash);

void mail_hash_set_corrupted(struct mail_hash *hash, const char *error);
void mail_hash_transaction_set_corrupted(struct mail_hash_transaction *trans,
					 const char *error);

#endif
