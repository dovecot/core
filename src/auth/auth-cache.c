/* Copyright (c) 2004-2018 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "array.h"
#include "lib-signals.h"
#include "hash.h"
#include "str.h"
#include "strescape.h"
#include "var-expand.h"
#include "auth-request.h"
#include "auth-cache.h"

#include <time.h>

struct auth_cache {
	HASH_TABLE(char *, struct auth_cache_node *) hash;
	struct auth_cache_node *head, *tail;
	struct event *event;

	size_t max_size, size_left;
	unsigned int ttl_secs, neg_ttl_secs;

	unsigned int hit_count, miss_count;
	unsigned int pos_entries, neg_entries;
	unsigned long long pos_size, neg_size;
};

static bool
auth_request_var_expand_tab_find(const char *key, unsigned int *idx_r)
{
	const struct var_expand_table *tab = auth_request_var_expand_static_tab;
	unsigned int i;

	for (i = 0; tab[i].key != NULL; i++) {
		if (strcmp(key, tab[i].key) == 0) {
			*idx_r = i;
			return TRUE;
		}
	}
	return FALSE;
}

static void
auth_cache_key_add_var(string_t *str, const char *data)
{
	if (str_len(str) > 0)
		str_append_c(str, '\t');
	str_append_c(str, '%');
	str_append_c(str, '{');
	str_append(str, data);
	str_append_c(str, '}');
}

static void auth_cache_key_add_tab_idx(string_t *str, unsigned int i)
{
	const struct var_expand_table *tab =
		&auth_request_var_expand_static_tab[i];

	if (str_len(str) > 0)
		str_append_c(str, '\t');
	str_append_c(str, '%');
	str_append_c(str, '{');
	str_append(str, tab->key);
	str_append_c(str, '}');
}

static char *auth_cache_parse_key_exclude(pool_t pool, const char *query,
					  const char *exclude_driver)
{
	string_t *str;
	bool key_seen[AUTH_REQUEST_VAR_TAB_COUNT];
	const char *extra_vars, *error ATTR_UNUSED;
	unsigned int i, tab_idx;

	memset(key_seen, 0, sizeof(key_seen));

	struct var_expand_program *prog;
	if (var_expand_program_create(query, &prog, &error) < 0) {
		e_debug(auth_event, "auth-cache: var_expand_program_create('%s') failed: %s",
			query, error);
		return p_strdup(pool, "");
	}

	const char *const *vars = var_expand_program_variables(prog);
	str = t_str_new(32);

	for (; *vars != NULL; vars++) {
		/* ignore any providers */
		if (strchr(*vars, ':') != NULL &&
		    !str_begins_with(*vars, "passdb:") &&
		    !str_begins_with(*vars, "userdb:")) {
			continue;
		} else if (!auth_request_var_expand_tab_find(*vars, &tab_idx)) {
			if (null_strcmp(*vars, exclude_driver) != 0)
				auth_cache_key_add_var(str, *vars);
		} else {
			i_assert(tab_idx < N_ELEMENTS(key_seen));
			key_seen[tab_idx] = TRUE;
		}
	}

	/* we rely on these being at the beginning */
	i_assert(AUTH_REQUEST_VAR_TAB_USER_IDX == 0);

	extra_vars = t_strdup(str_c(str));
	str_truncate(str, 0);
	for (i = 0; i < N_ELEMENTS(key_seen); i++) {
		if (key_seen[i])
			auth_cache_key_add_tab_idx(str, i);
	}

	if (*extra_vars != '\0') {
		if (str_len(str) > 0)
			str_append_c(str, '\t');
		str_append(str, extra_vars);
	}

	var_expand_program_free(&prog);

	return p_strdup(pool, str_c(str));
}

char *auth_cache_parse_key(pool_t pool, const char *query)
{
	return auth_cache_parse_key_exclude(pool, query, NULL);
}

char *auth_cache_parse_key_and_fields(pool_t pool, const char *query,
				      const ARRAY_TYPE(const_string) *fields,
				      const char *exclude_driver)
{
	if (array_is_empty(fields))
		return auth_cache_parse_key_exclude(pool, query, exclude_driver);

	string_t *full_query = t_str_new(128);
	str_append(full_query, query);

	unsigned int i, count;
	const char *const *str = array_get(fields, &count);
	for (i = 0; i < count; i += 2) {
		str_append_c(full_query, '\t');
		str_append(full_query, str[i + 1]);
	}
	return auth_cache_parse_key_exclude(pool, str_c(full_query),
					    exclude_driver);
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
	char *key = node->data;

	auth_cache_node_unlink(cache, node);

	cache->size_left += node->alloc_size;
	hash_table_remove(cache->hash, key);
	i_free(node);
}

static void sig_auth_cache_clear(const siginfo_t *si ATTR_UNUSED, void *context)
{
	struct auth_cache *cache = context;

	e_info(cache->event, "SIGHUP received, %u cache entries flushed",
	       auth_cache_clear(cache));
}

static void sig_auth_cache_stats(const siginfo_t *si ATTR_UNUSED, void *context)
{
	struct auth_cache *cache = context;
	unsigned int total_count;
	size_t cache_used;

	total_count = cache->hit_count + cache->miss_count;
	e_info(cache->event, "Authentication cache hits %u/%u (%u%%)",
	       cache->hit_count, total_count,
	       total_count == 0 ? 100 : (cache->hit_count * 100 / total_count));

	e_info(cache->event, "Authentication cache inserts: "
	       "positive: %u entries %llu bytes, "
	       "negative: %u entries %llu bytes",
	       cache->pos_entries, cache->pos_size,
	       cache->neg_entries, cache->neg_size);

	cache_used = cache->max_size - cache->size_left;
	e_info(cache->event, "Authentication cache current size: "
	       "%zu bytes used of %zu bytes (%u%%)",
	       cache_used, cache->max_size,
	       (unsigned int)(cache_used * 100ULL / cache->max_size));

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
	hash_table_create(&cache->hash, default_pool, 0, str_hash, strcmp);
	cache->max_size = max_size;
	cache->size_left = max_size;
	cache->ttl_secs = ttl_secs;
	cache->neg_ttl_secs = neg_ttl_secs;
	cache->event = event_create(auth_event);

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
	event_unref(&cache->event);
	i_free(cache);
}

unsigned int auth_cache_clear(struct auth_cache *cache)
{
	unsigned int ret = hash_table_count(cache->hash);

	while (cache->tail != NULL)
		auth_cache_node_destroy(cache, cache->tail);
	hash_table_clear(cache->hash, FALSE);
	return ret;
}

static bool auth_cache_node_is_user(struct auth_cache_node *node,
				    const char *username)
{
	const char *data = node->data, *suffix;

	/* The cache nodes begin with "P"/"U", passdb/userdb ID, optional
	   "+" master user, "\t" and then usually followed by the username.
	   It's too much trouble to keep track of all the cache keys, so we'll
	   just match it as if it was the username. If e.g. '%n' is used in the
	   cache key instead of '%u', it means that cache entries can be
	   removed only when @domain isn't in the username parameter. */
	if (*data != 'P' && *data != 'U')
		return FALSE;
	data++;

	while (*data >= '0' && *data <= '9')
		data++;
	if (*data == '+') {
		/* skip over +master_user */
		while (*data != '\t' && *data != '\0')
			data++;
	}
	if (*data != '\t')
		return FALSE;
	data++;

	return str_begins(data, username, &suffix) &&
		(suffix[0] == '\t' || suffix[0] == '\0');
}

static bool auth_cache_node_is_one_of_users(struct auth_cache_node *node,
					    const char *const *usernames)
{
	unsigned int i;

	for (i = 0; usernames[i] != NULL; i++) {
		if (auth_cache_node_is_user(node, usernames[i]))
			return TRUE;
	}
	return FALSE;
}

unsigned int auth_cache_clear_users(struct auth_cache *cache,
				    const char *const *usernames)
{
	struct auth_cache_node *node, *next;
	unsigned int ret = 0;

	for (node = cache->tail; node != NULL; node = next) {
		next = node->next;
		if (auth_cache_node_is_one_of_users(node, usernames)) {
			auth_cache_node_destroy(cache, node);
			ret++;
		}
	}
	return ret;
}

static const char *
auth_cache_escape(const char *string,
		  const struct auth_request *auth_request ATTR_UNUSED)
{
	/* cache key %variables are separated by tabs, make sure that there
	   are no tabs in the string */
	return str_tabescape(string);
}

static const char *
auth_request_expand_cache_key(const struct auth_request *request,
			      const char *key, const char *username)
{
	static bool error_logged = FALSE;
	const char *error;

	/* Uniquely identify the request's passdb/userdb with the P/U prefix
	   and by "%{id}", which expands to the passdb/userdb ID number. */
	key = t_strconcat(request->userdb_lookup ? "U" : "P", "%{id}",
		request->fields.master_user == NULL ? "" : "+%{master_user}",
		"\t", key, NULL);

	/* It's fine to have unknown %variables in the cache key.
	   For example db-ldap can have pass_attrs containing
	   %{ldap:fields} which are used for output, not as part of
	   the input needed for cache_key. Those could in theory be
	   filtered out early in the cache_key, but that gets more
	   problematic when it needs to support also filtering out
	   e.g. %{sha256:ldap:fields}. */
	string_t *value = t_str_new(128);
	unsigned int count = 0;
	const struct var_expand_table *table =
		auth_request_get_var_expand_table_full(request,
			username, &count);
	if (auth_request_var_expand_with_table(value, key, request, table,
					       auth_cache_escape, &error) < 0 &&
	    !error_logged) {
		error_logged = TRUE;
		e_error(authdb_event(request),
			"Failed to expand auth cache key %s: %s", key, error);
	}
	return str_c(value);
}

const char *
auth_cache_lookup(struct auth_cache *cache, const struct auth_request *request,
		  const char *key, struct auth_cache_node **node_r,
		  bool *expired_r, bool *neg_expired_r)
{
	struct auth_cache_node *node;
	const char *value;
	unsigned int ttl_secs;
	time_t now;

	*expired_r = FALSE;
	*neg_expired_r = FALSE;

	key = auth_request_expand_cache_key(request, key, request->fields.translated_username);
	node = hash_table_lookup(cache->hash, key);
	if (node == NULL) {
		cache->miss_count++;
		return NULL;
	}

	value = node->data + strlen(node->data) + 1;
	ttl_secs = *value == '\0' ? cache->neg_ttl_secs : cache->ttl_secs;

	now = time(NULL);
	if (node->created < now - (time_t)ttl_secs) {
		/* TTL expired */
		cache->miss_count++;
		*expired_r = TRUE;
	} else {
		/* move to head */
		if (node != cache->head) {
			auth_cache_node_unlink(cache, node);
			auth_cache_node_link_head(cache, node);
		}
		cache->hit_count++;
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
        struct auth_cache_node *node;
	size_t data_size, alloc_size, key_len, value_len = strlen(value);
	char *hash_key;

	if (*value == '\0' && cache->neg_ttl_secs == 0) {
		/* we're not caching negative entries */
		return;
	}

	key = auth_request_expand_cache_key(request, key, request->fields.translated_username);
	key_len = strlen(key);

	data_size = key_len + 1 + value_len + 1;
	alloc_size = sizeof(struct auth_cache_node) + data_size;

	/* make sure we have enough space */
	while (cache->size_left < alloc_size && cache->tail != NULL)
		auth_cache_node_destroy(cache, cache->tail);

	node = hash_table_lookup(cache->hash, key);
	if (node != NULL) {
		/* key is already in cache (probably expired), remove it */
		auth_cache_node_destroy(cache, node);
	}

	/* @UNSAFE */
	node = i_malloc(alloc_size);
	node->created = time(NULL);
	node->alloc_size = alloc_size;
	node->last_success = last_success;
	memcpy(node->data, key, key_len);
	memcpy(node->data + key_len + 1, value, value_len);

	auth_cache_node_link_head(cache, node);

	cache->size_left -= alloc_size;
	hash_key = node->data;
	hash_table_insert(cache->hash, hash_key, node);

	if (*value != '\0') {
		cache->pos_entries++;
		cache->pos_size += alloc_size;
	} else {
		cache->neg_entries++;
		cache->neg_size += alloc_size;
	}
}

void auth_cache_remove(struct auth_cache *cache,
		       const struct auth_request *request, const char *key)
{
	struct auth_cache_node *node;

	key = auth_request_expand_cache_key(request, key, request->fields.user);
	node = hash_table_lookup(cache->hash, key);
	if (node == NULL)
		return;

	auth_cache_node_destroy(cache, node);
}
