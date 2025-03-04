#ifndef DNS_CLIENT_CACHE_H
#define DNS_CLIENT_CACHE_H

struct dns_client;
struct dns_lookup_result;

/* Refresh the specified cache_key. dns_client_cache_entry() must be called
   afterwards, even on lookup failures. */
typedef void
dns_client_cache_refresh_callback_t(const char *cache_key, void *context);

struct dns_client_cache *
dns_client_cache_init(unsigned int ttl_secs,
		      dns_client_cache_refresh_callback_t *refresh_callback,
		      void *refresh_context);
#define dns_client_cache_init(ttl_secs, refresh_callback, refresh_context) \
	dns_client_cache_init(ttl_secs, \
		(dns_client_cache_refresh_callback_t *)refresh_callback, \
		1 ? refresh_context : \
		CALLBACK_TYPECHECK(refresh_callback, void (*)( \
			const char *, typeof(refresh_context))))

void dns_client_cache_deinit(struct dns_client_cache **cache);

bool dns_client_cache_lookup(struct dns_client_cache *cache,
			     const char *cache_key, pool_t pool,
			     struct dns_lookup_result *result_r);
void dns_client_cache_entry(struct dns_client_cache *cache,
			    const char *cache_key,
			    const struct dns_lookup_result *result);

#endif
