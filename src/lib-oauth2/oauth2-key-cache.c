/* Copyright (c) 2020 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "llist.h"
#include "buffer.h"
#include "hash2.h"
#include "dcrypt.h"
#include "oauth2.h"
#include "oauth2-private.h"

struct oauth2_key_cache_entry {
	const char *key_id;
	struct dcrypt_public_key *pubkey;
	buffer_t *hmac_key;
	struct oauth2_key_cache_entry *prev, *next;
};

struct oauth2_validation_key_cache {
	pool_t pool;
	struct hash2_table *keys;
	struct oauth2_key_cache_entry *list_start;
};

struct oauth2_validation_key_cache *oauth2_validation_key_cache_init(void)
{
	pool_t pool = pool_alloconly_create(MEMPOOL_GROWING"oauth2 key cache", 128);
	struct oauth2_validation_key_cache *cache =
		p_new(pool, struct oauth2_validation_key_cache, 1);
	cache->pool = pool;
	cache->keys = hash2_create(8, sizeof(struct oauth2_key_cache_entry),
				   hash2_str_hash, hash2_strcmp, NULL);
	return cache;
}

void oauth2_validation_key_cache_deinit(struct oauth2_validation_key_cache **_cache)
{
	struct oauth2_validation_key_cache *cache = *_cache;
	*_cache = NULL;
	if (cache == NULL)
		return;

	/* free resources */
	struct oauth2_key_cache_entry *entry = cache->list_start;
	while (entry != NULL) {
		if (entry->pubkey != NULL)
			dcrypt_key_unref_public(&entry->pubkey);
		entry = entry->next;
	}
	hash2_destroy(&cache->keys);
	pool_unref(&cache->pool);
}

int oauth2_validation_key_cache_lookup_pubkey(struct oauth2_validation_key_cache *cache,
					      const char *key_id,
					      struct dcrypt_public_key **pubkey_r)
{
	if (cache == NULL)
		return -1;
	struct oauth2_key_cache_entry *entry = hash2_lookup(cache->keys, key_id);
	if (entry == NULL || entry->pubkey == NULL)
		return -1;

	*pubkey_r = entry->pubkey;
	return 0;
}

int oauth2_validation_key_cache_lookup_hmac_key(struct oauth2_validation_key_cache *cache,
						const char *key_id,
						const buffer_t **hmac_key_r)
{
	if (cache == NULL)
		return -1;
	struct oauth2_key_cache_entry *entry = hash2_lookup(cache->keys, key_id);
	if (entry == NULL || entry->hmac_key == NULL ||
	    entry->hmac_key->used == 0)
		return -1;

	*hmac_key_r = entry->hmac_key;
	return 0;
}

void oauth2_validation_key_cache_insert_pubkey(struct oauth2_validation_key_cache *cache,
					       const char *key_id,
					       struct dcrypt_public_key *pubkey)
{
	if (cache == NULL)
		return;
	struct oauth2_key_cache_entry *entry = hash2_lookup(cache->keys, key_id);
	if (entry != NULL) {
		dcrypt_key_unref_public(&entry->pubkey);
		entry->pubkey = pubkey;
		if (entry->hmac_key != NULL)
			buffer_set_used_size(entry->hmac_key, 0);
		return;
	}
	entry = hash2_insert(cache->keys, key_id);
	entry->key_id = p_strdup(cache->pool, key_id);
	entry->pubkey = pubkey;
	DLLIST_PREPEND(&cache->list_start, entry);
}

void oauth2_validation_key_cache_insert_hmac_key(struct oauth2_validation_key_cache *cache,
						 const char *key_id,
						 const buffer_t *hmac_key)
{
	if (cache == NULL)
		return;
	struct oauth2_key_cache_entry *entry = hash2_lookup(cache->keys, key_id);
	if (entry != NULL) {
		dcrypt_key_unref_public(&entry->pubkey);
		if (entry->hmac_key == NULL)
			entry->hmac_key = buffer_create_dynamic(cache->pool, hmac_key->used);
		else
			buffer_set_used_size(entry->hmac_key, 0);
		buffer_append(entry->hmac_key, hmac_key->data, hmac_key->used);
		return;
	}
	entry = hash2_insert(cache->keys, key_id);
	entry->key_id = p_strdup(cache->pool, key_id);
	entry->hmac_key = buffer_create_dynamic(cache->pool, hmac_key->used);
	buffer_append(entry->hmac_key, hmac_key->data, hmac_key->used);
	DLLIST_PREPEND(&cache->list_start, entry);
}

int oauth2_validation_key_cache_evict(struct oauth2_validation_key_cache *cache,
				      const char *key_id)
{
	if (cache == NULL)
		return -1;
	struct oauth2_key_cache_entry *entry = hash2_lookup(cache->keys, key_id);
	if (entry == NULL)
		return -1;
	if (entry->pubkey != NULL)
		dcrypt_key_unref_public(&entry->pubkey);
	DLLIST_REMOVE(&cache->list_start, entry);
	hash2_remove(cache->keys, key_id);
	return 0;
}
