/* Copyright (c) 2010-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "wildcard-match.h"
#include "hash.h"
#include "llist.h"
#include "settings-parser.h"
#include "dns-util.h"
#include "strescape.h"
#include "master-service-private.h"
#include "master-service-settings.h"
#include "master-service-settings-cache.h"

/* we start with just a guess. it's updated later. */
#define CACHE_INITIAL_ENTRY_POOL_SIZE (1024*16)
#define CACHE_ADD_ENTRY_POOL_SIZE 1024

struct config_filter {
	struct config_filter *prev, *next;

	const char *local_name;
	struct ip_addr local_ip, remote_ip;
	unsigned int local_bits, remote_bits;
};

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
	HASH_TABLE(char *, struct settings_entry *) local_name_hash;
	HASH_TABLE(struct ip_addr *, struct settings_entry *) local_ip_hash;

	struct config_filter *filters;

	/* Initial size for new settings entry pools */
	size_t approx_entry_pool_size;
	/* number of bytes malloced by cached settings entries
	   (doesn't count memory used by hash table or global sets) */
	size_t cache_malloc_size;

	bool done_initial_lookup:1;
	bool service_uses_local:1;
	bool service_uses_remote:1;
};

struct master_service_settings_cache *
master_service_settings_cache_init(struct master_service *service,
				   const char *module, const char *service_name)
{
	struct master_service_settings_cache *cache;
	pool_t pool;

	pool = pool_alloconly_create(MEMPOOL_GROWING"master service settings cache",
				     1024*12);
	cache = p_new(pool, struct master_service_settings_cache, 1);
	cache->pool = pool;
	cache->service = service;
	cache->module = p_strdup(pool, module);
	cache->service_name = p_strdup(pool, service_name);
	cache->max_cache_size = (size_t)-1;
	return cache;
}

int master_service_settings_cache_init_filter(struct master_service_settings_cache *cache)
{
	const char *const *filters;
	const char *error;

	if (cache->filters != NULL)
		return 0;
	if (master_service_settings_get_filters(cache->service, &filters, &error) < 0) {
		i_error("master-service: cannot get filters: %s", error);
		return -1;
	}

	/* parse filters */
	while(*filters != NULL) {
		const char *const *keys = t_strsplit_tabescaped(*filters);
		struct config_filter *filter =
			p_new(cache->pool, struct config_filter, 1);
		while(*keys != NULL) {
			if (str_begins(*keys, "local-net=")) {
				(void)net_parse_range((*keys)+10,
					&filter->local_ip, &filter->local_bits);
			} else if (str_begins(*keys, "remote-net=")) {
				(void)net_parse_range((*keys)+11,
					&filter->remote_ip, &filter->remote_bits);
			} else if (str_begins(*keys, "local-name=")) {
				filter->local_name = p_strdup(cache->pool, (*keys)+11);
			}
			keys++;
		}
		DLLIST_PREPEND(&cache->filters, filter);
		filters++;
	}
	return 0;
}

static bool
match_local_name(const char *local_name,
		 const char *filter_local_name)
{
	/* Handle multiple names separated by spaces in local_name
	   * Ex: local_name "mail.domain.tld domain.tld mx.domain.tld" { ... } */
	const char *ptr;
	while((ptr = strchr(local_name, ' ')) != NULL) {
		if (dns_match_wildcard(filter_local_name,
		    t_strdup_until(local_name, ptr)) == 0)
			return TRUE;
		local_name = ptr+1;
	}
	return dns_match_wildcard(local_name, filter_local_name) == 0;
}

/* Remove any elements which there is no filter for */
static void
master_service_settings_cache_fix_input(struct master_service_settings_cache *cache,
				        const struct master_service_settings_input *input,
					struct master_service_settings_input *new_input)
{
	bool found_lip, found_rip, found_local_name;

	found_lip = found_rip = found_local_name = FALSE;

	struct config_filter *filter = cache->filters;
	while(filter != NULL) {
		if (filter->local_bits > 0 &&
		    net_is_in_network(&input->local_ip, &filter->local_ip,
				      filter->local_bits))
			found_lip = TRUE;
		if (filter->remote_bits > 0 &&
		    net_is_in_network(&input->remote_ip, &filter->remote_ip,
				      filter->remote_bits))
			found_rip = TRUE;
		if (input->local_name != NULL && filter->local_name != NULL &&
		    match_local_name(input->local_name, filter->local_name))
			found_local_name = TRUE;
		filter = filter->next;
	};

	*new_input = *input;

	if (!found_lip)
		i_zero(&new_input->local_ip);
	if (!found_rip)
		i_zero(&new_input->remote_ip);
	if (!found_local_name)
		new_input->local_name = NULL;
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
		i_assert(entry->parser != cache->global_parser);
		settings_parser_deinit(&entry->parser);
		pool_unref(&entry->pool);
	}
	hash_table_destroy(&cache->local_name_hash);
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
		if (hash_table_is_created(cache->local_name_hash)) {
			entry = hash_table_lookup(cache->local_name_hash,
						  input->local_name);
		}
	} else if (hash_table_is_created(cache->local_ip_hash) &&
		   input->local_ip.family != 0) {
		entry = hash_table_lookup(cache->local_ip_hash,
					  &input->local_ip);
	}

	if (entry != NULL) {
		if (entry->parser != cache->global_parser) {
			DLLIST2_REMOVE(&cache->oldest, &cache->newest, entry);
			DLLIST2_APPEND(&cache->oldest, &cache->newest, entry);
		}
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
	else if (entry->local_ip.family != 0)
		hash_table_remove(cache->local_ip_hash, &entry->local_ip);
	settings_parser_deinit(&entry->parser);
}

static struct setting_parser_context *
cache_add(struct master_service_settings_cache *cache,
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
		return parser;
	}

	if (input->local_name == NULL && input->local_ip.family == 0)
		return parser;

	if (!output->used_local) {
		/* use global settings, but add local_ip/host to hash tables
		   so we'll find them */
		pool = pool_alloconly_create("settings global entry", 256);
	} else if (cache->cache_malloc_size >= cache->max_cache_size) {
		/* free the oldest and reuse its pool */
		pool = cache->oldest->pool;
		setting_entry_detach(cache, cache->oldest);
		p_clear(pool); /* note: frees also entry */
	} else {
		pool_size = cache->approx_entry_pool_size != 0 ?
			cache->approx_entry_pool_size :
			CACHE_INITIAL_ENTRY_POOL_SIZE;
		pool = pool_alloconly_create("settings entry", pool_size);
	}
	entry = p_new(pool, struct settings_entry, 1);
	entry->pool = pool;
	entry_local_name = p_strdup(pool, input->local_name);
	entry->local_name = entry_local_name;
	entry->local_ip = input->local_ip;
	if (!output->used_local) {
		entry->parser = cache->global_parser;
		DLLIST2_APPEND(&cache->oldest_global, &cache->newest_global,
			       entry);
	} else {
		entry->parser = settings_parser_dup(parser, entry->pool);
		DLLIST2_APPEND(&cache->oldest, &cache->newest, entry);

		pool_size = pool_alloconly_get_total_used_size(pool);
		if (pool_size > cache->approx_entry_pool_size) {
			cache->approx_entry_pool_size = pool_size +
				CACHE_ADD_ENTRY_POOL_SIZE;
		}
	}
	cache->cache_malloc_size += pool_alloconly_get_total_alloc_size(pool);

	if (input->local_name != NULL) {
		if (!hash_table_is_created(cache->local_name_hash)) {
			hash_table_create(&cache->local_name_hash,
					  cache->pool, 0, str_hash, strcmp);
		}
		i_assert(hash_table_lookup(cache->local_name_hash,
					   entry_local_name) == NULL);
		hash_table_insert(cache->local_name_hash,
				  entry_local_name, entry);
	} else if (input->local_ip.family != 0) {
		if (!hash_table_is_created(cache->local_ip_hash)) {
			hash_table_create(&cache->local_ip_hash, cache->pool, 0,
					  net_ip_hash, net_ip_cmp);
		}
		i_assert(hash_table_lookup(cache->local_ip_hash,
					   &entry->local_ip) == NULL);
		hash_table_insert(cache->local_ip_hash,
				  &entry->local_ip, entry);
	}
	return entry->parser;
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
	if (cache->filters != NULL) {
		master_service_settings_cache_fix_input(cache, input, &new_input);
		if (cache_find(cache, &new_input, parser_r))
			return 0;
	}

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

	*parser_r = cache_add(cache, &new_input, &output,
			      cache->service->set_parser);
	return 0;
}
