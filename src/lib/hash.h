#ifndef HASH_H
#define HASH_H

/* Returns hash code. */
typedef unsigned int hash_callback_t(const void *p);
/* Returns 0 if the pointers are equal. */
typedef int hash_cmp_callback_t(const void *p1, const void *p2);

/* Create a new hash table. If initial_size is 0, the default value is used.
   If hash_cb or key_compare_cb is NULL, direct hashing/comparing is used.

   table_pool is used to allocate/free large hash tables, node_pool is used
   for smaller allocations and can also be alloconly pool. The pools must not
   be free'd before hash_table_destroy() is called. */
struct hash_table *
hash_table_create(pool_t table_pool, pool_t node_pool, unsigned int initial_size,
		  hash_callback_t *hash_cb, hash_cmp_callback_t *key_compare_cb);
void hash_table_destroy(struct hash_table **table);
/* Remove all nodes from hash table. If free_collisions is TRUE, the
   memory allocated from node_pool is freed, or discarded with
   alloconly pools. */
void hash_table_clear(struct hash_table *table, bool free_collisions);

void *hash_table_lookup(const struct hash_table *table, const void *key) ATTR_PURE;
bool hash_table_lookup_full(const struct hash_table *table,
			    const void *lookup_key,
			    void **orig_key, void **value);

/* Insert/update node in hash table. The difference is that hash_table_insert()
   replaces the key in table to given one, while hash_table_update() doesnt. */
void hash_table_insert(struct hash_table *table, void *key, void *value);
void hash_table_update(struct hash_table *table, void *key, void *value);

void hash_table_remove(struct hash_table *table, const void *key);
unsigned int hash_table_count(const struct hash_table *table) ATTR_PURE;

/* Iterates through all nodes in hash table. You may safely call hash_table_*()
   functions while iterating, but if you add any new nodes, they may or may
   not be called for in this iteration. */
struct hash_iterate_context *hash_table_iterate_init(struct hash_table *table);
bool hash_table_iterate(struct hash_iterate_context *ctx,
			void **key_r, void **value_r);
void hash_table_iterate_deinit(struct hash_iterate_context **ctx);

/* Hash table isn't resized, and removed nodes aren't removed from
   the list while hash table is freezed. Supports nesting. */
void hash_table_freeze(struct hash_table *table);
void hash_table_thaw(struct hash_table *table);

/* Copy all nodes from one hash table to another */
void hash_table_copy(struct hash_table *dest, struct hash_table *src);

/* hash function for strings */
unsigned int str_hash(const void *p) ATTR_PURE;
unsigned int strcase_hash(const void *p) ATTR_PURE;

#endif
