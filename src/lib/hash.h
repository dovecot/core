#ifndef __HASH_H
#define __HASH_H

/* Returns hash code. */
typedef unsigned int (*HashFunc) (const void *p);
/* Returns 0 if the pointers are equal. */
typedef int (*HashCompareFunc) (const void *p1, const void *p2);
typedef void (*HashForeachFunc) (void *key, void *value, void *context);

typedef struct _HashTable HashTable;

/* Create a new hash table. If initial_size is 0, the default value is used.
   If hash_func or key_compare_func is NULL, direct hashing/comparing
   is used. */
HashTable *hash_create(Pool pool, unsigned int initial_size,
		       HashFunc hash_func, HashCompareFunc key_compare_func);
void hash_destroy(HashTable *table);

#ifdef POOL_CHECK_LEAKS
#  define hash_destroy_clean(table) hash_destroy(table)
#else
#  define hash_destroy_clean(table)
#endif

void hash_clear(HashTable *table);

void *hash_lookup(HashTable *table, const void *key);
int hash_lookup_full(HashTable *table, const void *lookup_key,
		     void **orig_key, void **value);

/* Insert/update node in hash table. The difference is that hash_insert()
   replaces the key in table to given one, while hash_update() doesnt. */
void hash_insert(HashTable *table, const void *key, const void *value);
void hash_update(HashTable *table, const void *key, const void *value);

void hash_remove(HashTable *table, const void *key);
unsigned int hash_size(HashTable *table);

/* Calls the given function for each node in hash table. You may safely
   call hash_*() functions inside your function, but if you add any
   new nodes, they may or may not be called for in this foreach loop. */
void hash_foreach(HashTable *table, HashForeachFunc func, void *context);
/* Stop the active hash_foreach() loop */
void hash_foreach_stop(void);

/* Hash table isn't resized, and removed nodes aren't removed from
   the list while hash table is freezed. Supports nesting. */
void hash_freeze(HashTable *table);
void hash_thaw(HashTable *table);

/* hash function for strings */
unsigned int str_hash(const void *p);
unsigned int strcase_hash(const void *p);

#endif
