#ifndef DNS_CLIENT_CACHE_H
#define DNS_CLIENT_CACHE_H

struct dns_client;
struct dns_lookup_result;

struct dns_client_cache *
dns_client_cache_init(struct dns_client *client, struct event *event,
		      unsigned int ttl_secs);
void dns_client_cache_deinit(struct dns_client_cache **cache);

bool dns_client_cache_lookup(struct dns_client_cache *cache,
			     const char *cache_key, pool_t pool,
			     struct dns_lookup_result *result_r);
void dns_client_cache_entry(struct dns_client_cache *cache,
			    const char *cache_key,
			    const struct dns_lookup_result *result);

#endif
