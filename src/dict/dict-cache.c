/* Copyright (C) 2005 Timo Sirainen */

#include "lib.h"
#include "hash.h"
#include "dict.h"
#include "dict-cache.h"

struct dict_entry {
	int refcount;
	char *uri;
	struct dict *dict;
};

struct dict_cache {
	struct hash_table *dicts; /* uri -> struct dict_entry */
};

struct dict_cache *dict_cache_init(void)
{
	struct dict_cache *cache;

	cache = i_new(struct dict_cache, 1);
	cache->dicts = hash_create(default_pool, default_pool, 0, str_hash,
				   (hash_cmp_callback_t *)strcmp);
	return cache;
}

void dict_cache_deinit(struct dict_cache *cache)
{
	hash_destroy(&cache->dicts);
	i_free(cache);
}

struct dict *dict_cache_get(struct dict_cache *cache, const char *uri,
			    enum dict_data_type value_type,
			    const char *username)
{
	struct dict_entry *entry;

	entry = hash_lookup(cache->dicts, uri);
	if (entry == NULL) {
		entry = i_new(struct dict_entry, 1);
		entry->dict = dict_init(uri, value_type, username);
		entry->uri = i_strdup(uri);
		hash_insert(cache->dicts, entry->uri, entry);
	}
	entry->refcount++;
	return entry->dict;
}

void dict_cache_unref(struct dict_cache *cache, const char *uri)
{
	struct dict_entry *entry;

	entry = hash_lookup(cache->dicts, uri);
	i_assert(entry != NULL && entry->refcount > 0);

	if (--entry->refcount > 0)
		return;

	hash_remove(cache->dicts, uri);
	dict_deinit(&entry->dict);
	i_free(entry->uri);
	i_free(entry);
}
