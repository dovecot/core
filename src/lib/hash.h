#ifndef __HASH_H
#define __HASH_H

/* Returns hash code. */
typedef unsigned int (*HashFunc) (const void *p);
/* Returns 0 if the pointers are equal. */
typedef int (*HashCompareFunc) (const void *p1, const void *p2);
typedef void (*HashForeachFunc) (void *key, void *value, void *context);

/* Create a new hash table. If initial_size is 0, the default value is used.
   If hash_func or key_compare_func is NULL, direct hashing/comparing
   is used. */
struct hash_table *hash_create(pool_t node_pool, pool_t hash_pool,
			       unsigned int initial_size, HashFunc hash_func,
			       HashCompareFunc key_compare_func);
void hash_destroy(struct hash_table *table);

#ifdef POOL_CHECK_LEAKS
#  define hash_destroy_clean(table) hash_destroy(table)
#else
#  define hash_destroy_clean(table)
#endif

void hash_clear(struct hash_table *table);

void *hash_lookup(struct hash_table *table, const void *key);
int hash_lookup_full(struct hash_table *table, const void *lookup_key,
		     void **orig_key, void **value);

/* Insert/update node in hash table. The difference is that hash_insert()
   replaces the key in table to given one, while hash_update() doesnt. */
void hash_insert(struct hash_table *table, void *key, void *value);
void hash_update(struct hash_table *table, void *key, void *value);

void hash_remove(struct hash_table *table, const void *key);
unsigned int hash_size(struct hash_table *table);

/* Calls the given function for each node in hash table. You may safely
   call hash_*() functions inside your function, but if you add any
   new nodes, they may or may not be called for in this foreach loop. */
void hash_foreach(struct hash_table *table,
		  HashForeachFunc func, void *context);
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
