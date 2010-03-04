#ifndef AUTH_CACHE_H
#define AUTH_CACHE_H

struct auth_cache_node {
	struct auth_cache_node *prev, *next;

	time_t created;
	/* Total number of bytes used by this node */
	uint32_t alloc_size:31;
	/* TRUE if the user gave the correct password the last time. */
	uint32_t last_success:1;

	char data[4]; /* key \0 value \0 */
};

struct auth_cache;
struct auth_request;

/* Parses all %x variables from query and compresses them into tab-separated
   list, so it can be used as a cache key. */
char *auth_cache_parse_key(pool_t pool, const char *query);

/* Create a new cache. max_size specifies the maximum amount of memory in
   bytes to use for cache (it's not fully exact). ttl_secs specifies time to
   live for cache record, requests older than that are not used.
   neg_ttl_secs specifies the TTL for negative entries. */
struct auth_cache *auth_cache_new(size_t max_size, unsigned int ttl_secs,
				  unsigned int neg_ttl_secs);
void auth_cache_free(struct auth_cache **cache);

/* Clear the cache. */
void auth_cache_clear(struct auth_cache *cache);

/* Look key from cache. key should be the same string as returned by
   auth_cache_parse_key(). Returned node can't be used after any other
   auth_cache_*() calls. */
const char *
auth_cache_lookup(struct auth_cache *cache, const struct auth_request *request,
		  const char *key, struct auth_cache_node **node_r,
		  bool *expired_r, bool *neg_expired_r);
/* Insert key => value into cache. "" value means negative cache entry. */
void auth_cache_insert(struct auth_cache *cache, struct auth_request *request,
		       const char *key, const char *value, bool last_success);

/* Remove key from cache */
void auth_cache_remove(struct auth_cache *cache,
		       const struct auth_request *request,
		       const char *key);

#endif
