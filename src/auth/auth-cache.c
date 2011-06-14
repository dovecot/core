/* Copyright (c) 2004-2011 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "lib-signals.h"
#include "hash.h"
#include "str.h"
#include "strescape.h"
#include "var-expand.h"
#include "auth-request.h"
#include "auth-cache.h"

#include <time.h>

struct auth_cache {
	struct hash_table *hash;
	struct auth_cache_node *head, *tail;

	size_t size_left;
	unsigned int ttl_secs, neg_ttl_secs;

	unsigned int hit_count, miss_count;
	unsigned int pos_entries, neg_entries;
	unsigned long long pos_size, neg_size;
};

char *auth_cache_parse_key(pool_t pool, const char *query)
{
	string_t *str;
	char key_seen[256];
	uint8_t key;

	memset(key_seen, 0, sizeof(key_seen));

	str = str_new(pool, 32);
	for (; *query != '\0'; query++) {
		if (*query == '%' && query[1] != '\0') {
			query++;
                        key = var_get_key(query);
			if (key != '\0' && key != '%' && !key_seen[key]) {
				if (str_len(str) != 0)
					str_append_c(str, '\t');
				str_append_c(str, '%');
				str_append_c(str, key);

				/* @UNSAFE */
                                key_seen[key] = 1;
			}
		}
	}
	return str_free_without_data(&str);
}

static void
auth_cache_node_unlink(struct auth_cache *cache, struct auth_cache_node *node)
{
	if (node->prev != NULL)
		node->prev->next = node->next;
	else {
		/* unlinking tail */
		cache->tail = node->next;
	}

	if (node->next != NULL)
		node->next->prev = node->prev;
	else {
		/* unlinking head */
		cache->head = node->prev;
	}
}

static void
auth_cache_node_link_head(struct auth_cache *cache,
			  struct auth_cache_node *node)
{
	node->prev = cache->head;
	node->next = NULL;

	cache->head = node;
	if (node->prev != NULL)
		node->prev->next = node;
	else
		cache->tail = node;
}

static void
auth_cache_node_destroy(struct auth_cache *cache, struct auth_cache_node *node)
{
	auth_cache_node_unlink(cache, node);

	cache->size_left += node->alloc_size;
	hash_table_remove(cache->hash, node->data);
	i_free(node);
}

static void sig_auth_cache_clear(const siginfo_t *si ATTR_UNUSED, void *context)
{
	struct auth_cache *cache = context;

	i_info("SIGHUP received, clearing cache");
	auth_cache_clear(cache);
}

static void sig_auth_cache_stats(const siginfo_t *si ATTR_UNUSED, void *context)
{
	struct auth_cache *cache = context;
	unsigned int total_count;

	total_count = cache->hit_count + cache->miss_count;
	i_info("Authentication cache hits %u/%u (%u%%)",
	       cache->hit_count, total_count,
	       total_count == 0 ? 100 : (cache->hit_count * 100 / total_count));

	i_info("Authentication cache inserts: "
	       "positive: %u %lluB, negative: %u %lluB",
	       cache->pos_entries, cache->pos_size,
	       cache->neg_entries, cache->neg_size);

	/* reset counters */
	cache->hit_count = cache->miss_count = 0;
	cache->pos_entries = cache->neg_entries = 0;
	cache->pos_size = cache->neg_size = 0;
}

struct auth_cache *auth_cache_new(size_t max_size, unsigned int ttl_secs,
				  unsigned int neg_ttl_secs
)
{
	struct auth_cache *cache;

	cache = i_new(struct auth_cache, 1);
	cache->hash = hash_table_create(default_pool, default_pool, 0, str_hash,
					(hash_cmp_callback_t *)strcmp);
	cache->size_left = max_size;
	cache->ttl_secs = ttl_secs;
	cache->neg_ttl_secs = neg_ttl_secs;

	lib_signals_set_handler(SIGHUP, LIBSIG_FLAGS_SAFE,
				sig_auth_cache_clear, cache);
	lib_signals_set_handler(SIGUSR2, LIBSIG_FLAGS_SAFE,
				sig_auth_cache_stats, cache);
	return cache;
}

void auth_cache_free(struct auth_cache **_cache)
{
	struct auth_cache *cache = *_cache;

	*_cache = NULL;
	lib_signals_unset_handler(SIGHUP, sig_auth_cache_clear, cache);
	lib_signals_unset_handler(SIGUSR2, sig_auth_cache_stats, cache);

	auth_cache_clear(cache);
	hash_table_destroy(&cache->hash);
	i_free(cache);
}

void auth_cache_clear(struct auth_cache *cache)
{
	while (cache->tail != NULL)
		auth_cache_node_destroy(cache, cache->tail);
	hash_table_clear(cache->hash, FALSE);
}

const char *
auth_cache_lookup(struct auth_cache *cache, const struct auth_request *request,
		  const char *key, struct auth_cache_node **node_r,
		  bool *expired_r, bool *neg_expired_r)
{
	string_t *str;
	struct auth_cache_node *node;
	const char *value;
	unsigned int ttl_secs;
	time_t now;

	*expired_r = FALSE;
	*neg_expired_r = FALSE;

	/* %! is prepended automatically. it contains the passdb ID number. */
	str = t_str_new(256);
	var_expand(str, t_strconcat(request->userdb_lookup ? "U" : "P",
				    "%!/", key, NULL),
		   auth_request_get_var_expand_table(request, NULL));

	node = hash_table_lookup(cache->hash, str_c(str));
	if (node == NULL) {
		cache->miss_count++;
		return NULL;
	}
	cache->hit_count++;

	value = node->data + strlen(node->data) + 1;
	ttl_secs = *value == '\0' ? cache->neg_ttl_secs : cache->ttl_secs;

	now = time(NULL);
	if (node->created < now - (time_t)ttl_secs) {
		/* TTL expired */
		*expired_r = TRUE;
	} else {
		/* move to head */
		if (node != cache->head) {
			auth_cache_node_unlink(cache, node);
			auth_cache_node_link_head(cache, node);
		}
	}
	if (node->created < now - (time_t)cache->neg_ttl_secs)
		*neg_expired_r = TRUE;

	if (node_r != NULL)
		*node_r = node;

	return value;
}

void auth_cache_insert(struct auth_cache *cache, struct auth_request *request,
		       const char *key, const char *value, bool last_success)
{
	string_t *str;
        struct auth_cache_node *node;
	size_t data_size, alloc_size, value_len = strlen(value);
	char *current_username;

	if (*value == '\0' && cache->neg_ttl_secs == 0) {
		/* we're not caching negative entries */
		return;
	}

	/* store into cache using the translated username, except if we're doing
	   a master user login */
	current_username = request->user;
	if (request->translated_username != NULL &&
	    request->requested_login_user == NULL)
		request->user = t_strdup_noconst(request->translated_username);

	/* %! is prepended automatically. it contains the db ID number. */
	str = t_str_new(256);
	var_expand(str, t_strconcat(request->userdb_lookup ? "U" : "P",
				    "%!/", key, NULL),
		   auth_request_get_var_expand_table(request, NULL));

	request->user = current_username;

	data_size = str_len(str) + 1 + value_len + 1;
	alloc_size = sizeof(struct auth_cache_node) -
		sizeof(node->data) + data_size;

	/* make sure we have enough space */
	while (cache->size_left < alloc_size && cache->tail != NULL)
		auth_cache_node_destroy(cache, cache->tail);

	node = hash_table_lookup(cache->hash, str_c(str));
	if (node != NULL) {
		/* key is already in cache (probably expired), remove it */
		auth_cache_node_destroy(cache, node);
	}

	/* @UNSAFE */
	node = i_malloc(alloc_size);
	node->created = time(NULL);
	node->alloc_size = alloc_size;
	node->last_success = last_success;
	memcpy(node->data, str_data(str), str_len(str));
	memcpy(node->data + str_len(str) + 1, value, value_len);

	auth_cache_node_link_head(cache, node);

	cache->size_left -= alloc_size;
	hash_table_insert(cache->hash, node->data, node);

	if (*value != '\0') {
		cache->pos_entries++;
		cache->pos_size += alloc_size;
	} else {
		cache->neg_entries++;
		cache->neg_size += alloc_size;
	}
}

void auth_cache_remove(struct auth_cache *cache,
		       const struct auth_request *request,
		       const char *key)
{
	string_t *str;
	struct auth_cache_node *node;

	str = t_str_new(256);
	var_expand(str, key,
		   auth_request_get_var_expand_table(request, NULL));

	node = hash_table_lookup(cache->hash, str_c(str));
	if (node == NULL)
		return;

	auth_cache_node_destroy(cache, node);
}
