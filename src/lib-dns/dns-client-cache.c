/* Copyright (c) 2010-2024 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "hash.h"
#include "priorityq.h"
#include "dns-lookup.h"
#include "dns-client-cache.h"

struct dns_client_cache_entry {
	struct priorityq_item item;
	time_t expires;
	unsigned int ips_count;
	bool refresh:1;
	bool refreshing:1;

	char *cache_key;
	char *name;
	struct ip_addr *ips;
};

struct dns_client_cache {
	unsigned int ttl_secs;
	dns_client_cache_refresh_callback_t *refresh_callback;
	void *refresh_context;

	struct timeout *to_cache_clean;
	HASH_TABLE(char *, struct dns_client_cache_entry *) table;
	struct priorityq *queue;
};

static void dns_client_cache_clean(struct dns_client_cache *cache);

static int dns_client_cache_entry_cmp(const void *p1, const void *p2)
{
	const struct dns_client_cache_entry *entry1 = p1;
	const struct dns_client_cache_entry *entry2 = p2;
	return entry1->expires - entry2->expires;
}

static void dns_client_cache_entry_free(struct dns_client_cache_entry **_entry)
{
	struct dns_client_cache_entry *entry = *_entry;
	*_entry = NULL;
	i_free(entry->ips);
	i_free(entry->name);
	i_free(entry->cache_key);
	i_free(entry);
}

void dns_client_cache_entry(struct dns_client_cache *cache,
			    const char *cache_key,
			    const struct dns_lookup_result *result)
{
	if (cache == NULL || cache->ttl_secs == 0)
		return;

	/* start cache cleanup since put something there */
	if (cache->to_cache_clean == NULL)
		cache->to_cache_clean =
			timeout_add((cache->ttl_secs/2)*1000,
				     dns_client_cache_clean, cache);

	struct dns_client_cache_entry *entry =
		hash_table_lookup(cache->table, cache_key);
	if (result->ret < 0) {
		if (entry != NULL)
			entry->refreshing = FALSE;
		return;
	}
	if (entry != NULL) {
		/* remove entry */
		priorityq_remove(cache->queue, &entry->item);
		hash_table_remove(cache->table, entry->cache_key);
		dns_client_cache_entry_free(&entry);
	}
	entry = i_new(struct dns_client_cache_entry, 1);
	entry->expires = ioloop_time + cache->ttl_secs;
	entry->cache_key = i_strdup(cache_key);
	entry->name = i_strdup(result->name);
	entry->ips_count = result->ips_count;
	if (result->ips_count > 0) {
		entry->ips = i_memdup(result->ips,
				      sizeof(struct ip_addr) * result->ips_count);
	}
	priorityq_add(cache->queue, &entry->item);
	hash_table_insert(cache->table, entry->cache_key, entry);
}

static void dns_client_cache_entry_refresh(struct dns_client_cache *cache,
					   struct dns_client_cache_entry *entry)
{
	/* about to expire, next lookup should go to client */
	entry->refresh = TRUE;
	/* ensure we don't trigger this again. this gets
	   changed in dns_client_cache_entry(). */
	entry->refreshing = TRUE;
	cache->refresh_callback(entry->cache_key, cache->refresh_context);
	/* reset back to false to allow further lookups to use cache while
	   the entry is being refreshed. */
	entry->refresh = FALSE;
}

bool dns_client_cache_lookup(struct dns_client_cache *cache,
			     const char *cache_key, pool_t pool,
			     struct dns_lookup_result *result_r)
{
	if (cache == NULL || cache->ttl_secs == 0)
		return FALSE;
	struct dns_client_cache_entry *entry =
		hash_table_lookup(cache->table, cache_key);
	if (entry == NULL)
		return FALSE;
	if (entry->expires <= ioloop_time) {
		priorityq_remove(cache->queue, &entry->item);
		hash_table_remove(cache->table, entry->cache_key);
		dns_client_cache_entry_free(&entry);
		return FALSE;
	}
	if (entry->refresh)
		return FALSE;
	i_zero(result_r);
	result_r->name = p_strdup(pool, entry->name);
	result_r->ips_count = entry->ips_count;
	if (entry->ips_count > 0) {
		result_r->ips =
			p_memdup(pool, entry->ips,
				 sizeof(struct ip_addr) * entry->ips_count);
	}
	if (!entry->refreshing &&
	    entry->expires <= ioloop_time + cache->ttl_secs / 2)
		dns_client_cache_entry_refresh(cache, entry);
	return TRUE;
}

static void dns_client_cache_clean(struct dns_client_cache *cache)
{
	while (priorityq_count(cache->queue) > 0) {
		struct priorityq_item *item = priorityq_peek(cache->queue);
		struct dns_client_cache_entry *entry =
			container_of(item, struct dns_client_cache_entry, item);
		if (entry->expires <= ioloop_time) {
			/* drop item */
			(void)priorityq_pop(cache->queue);
			hash_table_remove(cache->table, entry->cache_key);
			dns_client_cache_entry_free(&entry);
		} else {
			/* no more entries that need attention */
			break;
		}
	}

	/* stop cleaning cache if it becomes empty */
	if (priorityq_count(cache->queue) == 0)
		timeout_remove(&cache->to_cache_clean);
}

#undef dns_client_cache_init
struct dns_client_cache *
dns_client_cache_init(unsigned int ttl_secs,
		      dns_client_cache_refresh_callback_t *refresh_callback,
		      void *refresh_context)
{
	struct dns_client_cache *cache = i_new(struct dns_client_cache, 1);
	cache->refresh_callback = refresh_callback;
	cache->refresh_context = refresh_context;
	cache->ttl_secs = ttl_secs;
	hash_table_create(&cache->table, default_pool, 0,
			  strfastcase_hash, strcmp);
	cache->queue = priorityq_init(dns_client_cache_entry_cmp, 0);
	return cache;
}

void dns_client_cache_deinit(struct dns_client_cache **_cache)
{
	struct dns_client_cache *cache = *_cache;

	if (cache == NULL)
		return;
	*_cache = NULL;
	while (priorityq_count(cache->queue) > 0) {
		struct priorityq_item *item = priorityq_pop(cache->queue);
		struct dns_client_cache_entry *entry =
			container_of(item, struct dns_client_cache_entry, item);
		hash_table_remove(cache->table, entry->cache_key);
		dns_client_cache_entry_free(&entry);
	}
	timeout_remove(&cache->to_cache_clean);
	hash_table_destroy(&cache->table);
	priorityq_deinit(&cache->queue);
	i_free(cache);
}
