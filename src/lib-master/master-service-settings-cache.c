/* Copyright (c) 2010-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "hash.h"
#include "llist.h"
#include "settings-parser.h"
#include "master-service-private.h"
#include "master-service-settings.h"
#include "master-service-settings-cache.h"

/* we start with just a guess. it's updated later. */
#define CACHE_INITIAL_ENTRY_POOL_SIZE (1024*16)
#define CACHE_ADD_ENTRY_POOL_SIZE 1024

struct settings_entry {
	struct settings_entry *prev, *next;

	pool_t pool;
	const char *local_name;
	struct ip_addr local_ip;

	struct setting_parser_context *parser;
};

struct master_service_settings_cache {
	pool_t pool;

	struct master_service *service;
	const char *module;
	const char *service_name;
	size_t max_cache_size;

	/* global settings for this service (after they've been read) */
	struct setting_parser_context *global_parser;

	/* cache for other settings (local_ip/local_name set) */
	struct settings_entry *oldest, *newest;
	/* separate list for entries whose parser=global_parser */
	struct settings_entry *oldest_global, *newest_global;
	/* local_name, local_ip => struct settings_entry */
	struct hash_table *local_name_hash;
	struct hash_table *local_ip_hash;

	/* Initial size for new settings entry pools */
	size_t approx_entry_pool_size;
	/* number of bytes malloced by cached settings entries
	   (doesn't count memory used by hash table or global sets) */
	size_t cache_malloc_size;

	unsigned int done_initial_lookup:1;
	unsigned int service_uses_local:1;
	unsigned int service_uses_remote:1;
};

struct master_service_settings_cache *
master_service_settings_cache_init(struct master_service *service,
				   const char *module, const char *service_name)
{
	struct master_service_settings_cache *cache;
	pool_t pool;

	pool = pool_alloconly_create("master service settings cache", 1024*32);
	cache = p_new(pool, struct master_service_settings_cache, 1);
	cache->pool = pool;
	cache->service = service;
	cache->module = p_strdup(pool, module);
	cache->service_name = p_strdup(pool, service_name);
	cache->max_cache_size = (size_t)-1;
	return cache;
}

void master_service_settings_cache_deinit(struct master_service_settings_cache **_cache)
{
	struct master_service_settings_cache *cache = *_cache;
	struct settings_entry *entry, *next;

	/* parsers need to be deinitialized, because they reference the pool */
	for (entry = cache->oldest_global; entry != NULL; entry = next) {
		next = entry->next;
		i_assert(entry->parser == cache->global_parser);
		pool_unref(&entry->pool);
	}
	for (entry = cache->oldest; entry != NULL; entry = next) {
		next = entry->next;
		settings_parser_deinit(&entry->parser);
		pool_unref(&entry->pool);
	}
	if (cache->local_name_hash != NULL)
		hash_table_destroy(&cache->local_name_hash);
	if (cache->local_ip_hash != NULL)
		hash_table_destroy(&cache->local_ip_hash);
	if (cache->global_parser != NULL)
		settings_parser_deinit(&cache->global_parser);
	pool_unref(&cache->pool);
}

static bool
cache_can_return_global(struct master_service_settings_cache *cache,
			const struct master_service_settings_input *input)
{
	if (cache->service_uses_local) {
		if (input->local_name != NULL || input->local_ip.family != 0)
			return FALSE;
	}
	if (cache->service_uses_remote) {
		if (input->remote_ip.family != 0)
			return FALSE;
	}
	return TRUE;
}

static bool
cache_find(struct master_service_settings_cache *cache,
	   const struct master_service_settings_input *input,
	   const struct setting_parser_context **parser_r)
{
	struct settings_entry *entry = NULL;

	if (!cache->done_initial_lookup)
		return FALSE;

	if (cache_can_return_global(cache, input)) {
		if (cache->global_parser != NULL) {
			*parser_r = cache->global_parser;
			return TRUE;
		}
		return FALSE;
	}

	if (cache->service_uses_remote)
		return FALSE;

	/* see if we have it already in cache. if local_name is specified,
	   don't even try to use local_ip (even though we have it), because
	   there may be different settings specifically for local_name */
	if (input->local_name != NULL) {
		if (cache->local_name_hash != NULL) {
			entry = hash_table_lookup(cache->local_name_hash,
						  input->local_name);
		}
	} else if (cache->local_ip_hash != NULL &&
		   input->local_ip.family != 0) {
		entry = hash_table_lookup(cache->local_ip_hash,
					  &input->local_ip);
	}

	if (entry != NULL) {
		*parser_r = entry->parser;
		return TRUE;
	}
	return FALSE;
}

static void
setting_entry_detach(struct master_service_settings_cache *cache,
		     struct settings_entry *entry)
{
	DLLIST2_REMOVE(&cache->oldest, &cache->newest, entry);
	cache->cache_malloc_size -=
		pool_alloconly_get_total_alloc_size(entry->pool);

	if (entry->local_name != NULL)
		hash_table_remove(cache->local_name_hash, entry->local_name);
	if (entry->local_ip.family != 0)
		hash_table_remove(cache->local_ip_hash, &entry->local_ip);
	settings_parser_deinit(&entry->parser);
}

static void cache_add(struct master_service_settings_cache *cache,
		      const struct master_service_settings_input *input,
		      const struct master_service_settings_output *output,
		      struct setting_parser_context *parser)
{
	struct settings_entry *entry;
	pool_t pool;
	size_t pool_size;
	char *entry_local_name;

	if (!output->used_local && !output->used_remote) {
		/* these are same as global settings */
		if (cache->global_parser == NULL) {
			cache->global_parser =
				settings_parser_dup(parser, cache->pool);
		}
	}
	if (cache->service_uses_remote) {
		/* for now we don't try to handle caching remote IPs */
		return;
	}

	if (input->local_name == NULL && input->local_ip.family == 0)
		return;

	if (!output->used_local) {
		/* use global settings, but add local_ip/host to hash tables
		   so we'll find them */
		pool = pool_alloconly_create("settings global entry", 256);
		entry = p_new(pool, struct settings_entry, 1);
	} else if (cache->cache_malloc_size >= cache->max_cache_size) {
		/* free the oldest and reuse its pool */
		entry = cache->oldest;
		pool = entry->pool;
		setting_entry_detach(cache, entry);
		p_clear(pool);
	} else {
		pool_size = cache->approx_entry_pool_size != 0 ?
			cache->approx_entry_pool_size :
			CACHE_INITIAL_ENTRY_POOL_SIZE;
		pool = pool_alloconly_create("settings entry", pool_size);
		entry = p_new(pool, struct settings_entry, 1);
	}
	entry->pool = pool;
	entry_local_name = p_strdup(pool, input->local_name);
	entry->local_name = entry_local_name;
	entry->local_ip = input->local_ip;
	if (!output->used_local) {
		entry->parser = cache->global_parser;
		DLLIST2_PREPEND(&cache->oldest_global, &cache->newest_global,
				entry);
	} else {
		entry->parser = settings_parser_dup(parser, entry->pool);
		DLLIST2_PREPEND(&cache->oldest, &cache->newest, entry);

		pool_size = pool_alloconly_get_total_used_size(pool);
		if (pool_size > cache->approx_entry_pool_size) {
			cache->approx_entry_pool_size = pool_size +
				CACHE_ADD_ENTRY_POOL_SIZE;
		}
	}
	cache->cache_malloc_size += pool_alloconly_get_total_alloc_size(pool);

	if (input->local_name != NULL) {
		if (cache->local_name_hash == NULL) {
			cache->local_name_hash =
				hash_table_create(default_pool, cache->pool, 0,
						  str_hash,
						  (hash_cmp_callback_t *)strcmp);
		}
		hash_table_insert(cache->local_name_hash,
				  entry_local_name, entry);
	}
	if (input->local_ip.family != 0) {
		if (cache->local_ip_hash == NULL) {
			cache->local_ip_hash =
				hash_table_create(default_pool, cache->pool, 0,
						  (hash_callback_t *)net_ip_hash,
						  (hash_cmp_callback_t *)net_ip_cmp);
		}
		hash_table_insert(cache->local_ip_hash,
				  &entry->local_ip, entry);
	}
}

int master_service_settings_cache_read(struct master_service_settings_cache *cache,
				       const struct master_service_settings_input *input,
				       const struct dynamic_settings_parser *dyn_parsers,
				       const struct setting_parser_context **parser_r,
				       const char **error_r)
{
	struct master_service_settings_output output;
	struct master_service_settings_input new_input;
	const struct master_service_settings *set;

	i_assert(null_strcmp(input->module, cache->module) == 0);
	i_assert(null_strcmp(input->service, cache->service_name) == 0);

	if (cache_find(cache, input, parser_r))
		return 0;

	new_input = *input;
	if (dyn_parsers != NULL) {
		settings_parser_dyn_update(cache->pool, &new_input.roots,
					   dyn_parsers);
	}
	if (master_service_settings_read(cache->service, &new_input,
					 &output, error_r) < 0)
		return -1;

	if (!cache->done_initial_lookup) {
		cache->done_initial_lookup = TRUE;
		cache->service_uses_local = output.service_uses_local;
		cache->service_uses_remote = output.service_uses_remote;

		set = master_service_settings_get(cache->service);
		cache->max_cache_size = set->config_cache_size;
	}

	if (output.used_local && !cache->service_uses_local) {
		*error_r = "BUG: config unexpectedly returned local settings";
		return -1;
	}
	if (output.used_remote && !cache->service_uses_remote) {
		*error_r = "BUG: config unexpectedly returned remote settings";
		return -1;
	}

	cache_add(cache, &new_input, &output, cache->service->set_parser);
	*parser_r = cache->service->set_parser;
	return 0;
}
