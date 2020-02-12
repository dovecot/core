#ifndef HASH2_H
#define HASH2_H

#include "hash.h"

struct hash2_iter {
	struct hash2_value *value, *next_value;
	unsigned int key_hash;
};

/* Returns hash code for the key. */
typedef unsigned int hash2_key_callback_t(const void *key);
/* Returns TRUE if the key matches the value. */
typedef bool hash2_cmp_callback_t(const void *key, const void *value,
				  void *context);

/* Create a new hash table. If initial_size is 0, the default value is used. */
struct hash2_table *
hash2_create(unsigned int initial_size, unsigned int value_size,
	     hash2_key_callback_t *key_hash_cb,
	     hash2_cmp_callback_t *key_compare_cb, void *context) ATTR_NULL(5);
void hash2_destroy(struct hash2_table **hash);
/* Remove all nodes from hash table. */
void hash2_clear(struct hash2_table *hash);

void *hash2_lookup(const struct hash2_table *hash, const void *key) ATTR_PURE;
/* Iterate through all nodes with the given hash. iter must initially be
   zero-filled. */
void *hash2_iterate(const struct hash2_table *hash,
		    unsigned int key_hash, struct hash2_iter *iter);
/* Insert node to the hash table and returns pointer to the value that can be
   written to. Assumes it doesn't already exist (or that a duplicate entry
   is wanted). */
void *hash2_insert(struct hash2_table *hash, const void *key);
/* Like hash2_insert(), but insert directly using a hash. */
void *hash2_insert_hash(struct hash2_table *hash, unsigned int key_hash);
/* Remove a node. */
void hash2_remove(struct hash2_table *hash, const void *key);
/* Remove the last node iterator returned. Iterating continues from the next
   node. */
void hash2_remove_iter(struct hash2_table *hash, struct hash2_iter *iter);
/* Return the number of nodes in hash table. */
unsigned int hash2_count(const struct hash2_table *hash) ATTR_PURE;

/* can be used with string keys */
static inline bool hash2_strcmp(const void *a, const void *b, void *ctx ATTR_UNUSED)
{
	return strcmp(a, b) == 0;
}

static inline unsigned int hash2_str_hash(const void *key)
{
	return str_hash(key);
}

#endif
