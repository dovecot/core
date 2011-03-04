/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "primes.h"
#include "hash2.h"

#define HASH_TABLE_MIN_SIZE 131

struct hash2_value {
	struct hash2_value *next;
	unsigned int key_hash;
	/* user_data[value_size] */
};
ARRAY_DEFINE_TYPE(hash2_value, struct hash2_value *);

struct hash2_table {
	unsigned int count;
	unsigned int initial_size;
	unsigned int hash_table_size;
	unsigned int value_size;

	pool_t value_pool;
	struct hash2_value *deleted_values;

	ARRAY_TYPE(hash2_value) hash_table;

	hash2_key_callback_t *key_hash_cb;
	hash2_cmp_callback_t *key_compare_cb;
	void *context;
};

static void hash2_alloc_table(struct hash2_table *hash, unsigned int size)
{
	hash->hash_table_size = size;

	i_array_init(&hash->hash_table, hash->hash_table_size);
	(void)array_idx_modifiable(&hash->hash_table, hash->hash_table_size-1);
}

struct hash2_table *
hash2_create(unsigned int initial_size, unsigned int value_size,
	     hash2_key_callback_t *key_hash_cb,
	     hash2_cmp_callback_t *key_compare_cb, void *context)
{
	struct hash2_table *hash;

	hash = i_new(struct hash2_table, 1);
	hash->initial_size = I_MAX(initial_size, HASH_TABLE_MIN_SIZE);
	hash->value_size = value_size;
	hash->key_hash_cb = key_hash_cb;
	hash->key_compare_cb = key_compare_cb;
	hash->context = context;

	hash->value_pool = pool_alloconly_create("hash2 value pool", 16384);
	hash2_alloc_table(hash, hash->initial_size);
	return hash;
}

void hash2_destroy(struct hash2_table **_hash)
{
	struct hash2_table *hash = *_hash;

	*_hash = NULL;
	array_free(&hash->hash_table);
	pool_unref(&hash->value_pool);
	i_free(hash);
}

void hash2_clear(struct hash2_table *hash)
{
	array_free(&hash->hash_table);
	hash2_alloc_table(hash, hash->initial_size);
	p_clear(hash->value_pool);
	hash->count = 0;
	hash->deleted_values = NULL;
}

static void hash2_resize(struct hash2_table *hash, bool grow)
{
	ARRAY_TYPE(hash2_value) old_hash_table;
	struct hash2_value *const *old_hash, *value, **valuep, *next;
	unsigned int next_size, old_count, i, idx;
	float nodes_per_list;

	nodes_per_list = (float)hash->count / (float)hash->hash_table_size;
	if (nodes_per_list > 0.3 && nodes_per_list < 2.0)
		return;

	next_size = I_MAX(primes_closest(hash->count + 1), hash->initial_size);
	if (hash->hash_table_size >= next_size &&
	    (grow || next_size == hash->hash_table_size))
		return;

	old_hash_table = hash->hash_table;
	hash2_alloc_table(hash, next_size);

	old_count = array_count(&old_hash_table);
	for (i = 0; i < old_count; i++) {
		old_hash = array_idx(&old_hash_table, i);
		for (value = *old_hash; value != NULL; value = next) {
			next = value->next;

			idx = value->key_hash % hash->hash_table_size;
			valuep = array_idx_modifiable(&hash->hash_table, idx);
			value->next = *valuep;
			*valuep = value;
		}
	}
	array_free(&old_hash_table);
}

void *hash2_lookup(const struct hash2_table *hash, const void *key)
{
	unsigned int key_hash = hash->key_hash_cb(key);
	struct hash2_value *const *valuep;
	struct hash2_value *value;
	void *user_value;

	valuep = array_idx(&hash->hash_table, key_hash % hash->hash_table_size);
	value = *valuep;
	while (value != NULL) {
		if (value->key_hash == key_hash) {
			user_value = value + 1;
			if (hash->key_compare_cb(key, user_value,
						 hash->context))
				return user_value;
		}
		value = value->next;
	}
	return NULL;
}

void *hash2_iterate(const struct hash2_table *hash,
		    unsigned int key_hash, struct hash2_iter *iter)
{
	struct hash2_value *const *valuep;

	if (iter->value == NULL) {
		iter->key_hash = key_hash;
		valuep = array_idx(&hash->hash_table,
				   key_hash % hash->hash_table_size);
		iter->next_value = *valuep;
	}
	while (iter->next_value != NULL) {
		if (iter->next_value->key_hash == key_hash) {
			iter->value = iter->next_value;
			iter->next_value = iter->next_value->next;
			return iter->value + 1;
		}
		iter->next_value = iter->next_value->next;
	}
	return NULL;
}

void *hash2_insert(struct hash2_table *hash, const void *key)
{
	return hash2_insert_hash(hash, hash->key_hash_cb(key));
}

void *hash2_insert_hash(struct hash2_table *hash, unsigned int key_hash)
{
	struct hash2_value *value, **valuep;

	hash2_resize(hash, TRUE);

	if (hash->deleted_values != NULL) {
		value = hash->deleted_values;
		hash->deleted_values = value->next;
		value->next = NULL;
		memset(value + 1, 0, hash->value_size);
	} else {
		value = p_malloc(hash->value_pool,
				 sizeof(*value) + hash->value_size);
	}
	value->key_hash = key_hash;

	valuep = array_idx_modifiable(&hash->hash_table,
				      key_hash % hash->hash_table_size);
	value->next = *valuep;
	*valuep = value;

	hash->count++;
	return value + 1;
}

static void
hash2_remove_value_p(struct hash2_table *hash, struct hash2_value **valuep)
{
	struct hash2_value *deleted_value;

	deleted_value = *valuep;
	*valuep = deleted_value->next;

	deleted_value->next = hash->deleted_values;
	hash->deleted_values = deleted_value;

	hash->count--;
}

void hash2_remove(struct hash2_table *hash, const void *key)
{
	unsigned int key_hash = hash->key_hash_cb(key);
	struct hash2_value **valuep;

	valuep = array_idx_modifiable(&hash->hash_table,
				      key_hash % hash->hash_table_size);
	while (*valuep != NULL) {
		if ((*valuep)->key_hash == key_hash &&
		    hash->key_compare_cb(key, (*valuep) + 1, hash->context)) {
			hash2_remove_value_p(hash, valuep);
			hash2_resize(hash, FALSE);
			return;
		}
		valuep = &(*valuep)->next;
	}
	i_panic("hash2_remove(): key not found");
}

void hash2_remove_iter(struct hash2_table *hash, struct hash2_iter *iter)
{
	struct hash2_value **valuep, *next;

	valuep = array_idx_modifiable(&hash->hash_table,
				      iter->key_hash % hash->hash_table_size);
	while (*valuep != NULL) {
		if (*valuep == iter->value) {
			next = (*valuep)->next;
			/* don't allow resizing, otherwise iterating would
			   break completely */
			hash2_remove_value_p(hash, valuep);
			iter->next_value = next;
			return;
		}
		valuep = &(*valuep)->next;
	}
	i_panic("hash2_remove_value(): key/value not found");
}

unsigned int hash2_count(const struct hash2_table *hash)
{
	return hash->count;
}
