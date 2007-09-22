/* Copyright (c) 2005-2007 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "hash.h"
#include "dict.h"
#include "dict-cache.h"

struct dict_entry {
	int refcount;
	char *user_uri;
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
	char *user_uri;

	user_uri = i_strdup_printf("%s\t%s", username, uri);
	entry = hash_lookup(cache->dicts, user_uri);
	if (entry == NULL) {
		entry = i_new(struct dict_entry, 1);
		entry->dict = dict_init(uri, value_type, username);
		entry->user_uri = user_uri;
		hash_insert(cache->dicts, entry->user_uri, entry);
	} else {
		i_free(user_uri);
	}
	entry->refcount++;
	return entry->dict;
}

void dict_cache_unref(struct dict_cache *cache, const char *uri,
		      const char *username)
{
	struct dict_entry *entry;

	t_push();
	entry = hash_lookup(cache->dicts,
			    t_strdup_printf("%s\t%s", username, uri));
	i_assert(entry != NULL && entry->refcount > 0);

	if (--entry->refcount == 0) {
		hash_remove(cache->dicts, entry->user_uri);
		dict_deinit(&entry->dict);
		i_free(entry->user_uri);
		i_free(entry);
	}
	t_pop();
}
