#ifndef __HASH_H
#define __HASH_H

/* Returns hash code. */
typedef unsigned int hash_callback_t(const void *p);
/* Returns 0 if the pointers are equal. */
typedef int hash_cmp_callback_t(const void *p1, const void *p2);
typedef void hash_foreach_callback_t(void *key, void *value, void *context);

/* Create a new hash table. If initial_size is 0, the default value is used.
   If hash_cb or key_compare_cb is NULL, direct hashing/comparing is used.

   table_pool is used to allocate/free large hash tables, node_pool is used
   for smaller allocations and can also be alloconly pool. The pools must not
   be free'd before hash_destroy() is called. */
struct hash_table *
hash_create(pool_t table_pool, pool_t node_pool, size_t initial_size,
	    hash_callback_t *hash_cb, hash_cmp_callback_t *key_compare_cb);
void hash_destroy(struct hash_table *table);

/* Remove all nodes from hash table. If free_collisions is TRUE, the
   memory allocated from node_pool is freed, or discarded with
   alloconly pools. */
void hash_clear(struct hash_table *table, int free_collisions);

void *hash_lookup(struct hash_table *table, const void *key);
int hash_lookup_full(struct hash_table *table, const void *lookup_key,
		     void **orig_key, void **value);

/* Insert/update node in hash table. The difference is that hash_insert()
   replaces the key in table to given one, while hash_update() doesnt. */
void hash_insert(struct hash_table *table, void *key, void *value);
void hash_update(struct hash_table *table, void *key, void *value);

void hash_remove(struct hash_table *table, const void *key);
size_t hash_size(struct hash_table *table);

/* Calls the given function for each node in hash table. You may safely
   call hash_*() functions inside your function, but if you add any
   new nodes, they may or may not be called for in this foreach loop. */
void hash_foreach(struct hash_table *table,
		  hash_foreach_callback_t *callback, void *context);
/* Stop the active hash_foreach() loop */
void hash_foreach_stop(void);

/* Hash table isn't resized, and removed nodes aren't removed from
   the list while hash table is freezed. Supports nesting. */
void hash_freeze(struct hash_table *table);
void hash_thaw(struct hash_table *table);

/* hash function for strings */
unsigned int str_hash(const void *p);
unsigned int strcase_hash(const void *p);

#endif
