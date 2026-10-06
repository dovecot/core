/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "hash.h"
#include "settings.h"
#include "iostream-ssl-private.h"

struct ssl_iostream_context_cache {
	bool server;
	const struct ssl_iostream_settings *set;
	/* ALPN protocols are a property of the SSL_CTX, so they must be part
	   of the cache key. Otherwise whoever creates the context first would
	   decide the ALPN for everybody else using the same settings. */
	const char *const *application_protocols;
};

static pool_t ssl_iostream_contexts_pool;
static HASH_TABLE(struct ssl_iostream_context_cache *,
		  struct ssl_iostream_context *) ssl_iostream_contexts;

static unsigned int
ssl_iostream_context_cache_hash(const struct ssl_iostream_context_cache *cache)
{
	unsigned int n, i, g, h = 0;
	const char *const cert[] = {
		cache->set->cert.cert.content,
		cache->set->alt_cert.cert.content
	};

	/* checking for different certs is typically good enough,
	   and it should be enough to check only the first few bytes (after the
	   "BEGIN CERTIFICATE" line). */
	for (n = 0; n < N_ELEMENTS(cert); n++) {
		if (cert[n] == NULL)
			continue;

		for (i = 0; i < 64 && cert[n][i] != '\0'; i++) {
			h = (h << 4) + cert[n][i];
			if ((g = h & 0xf0000000UL) != 0) {
				h = h ^ (g >> 24);
				h = h ^ g;
			}
		}
	}
	for (n = 0; cache->application_protocols != NULL &&
	     cache->application_protocols[n] != NULL; n++)
		h ^= str_hash(cache->application_protocols[n]);
	return h ^ (cache->server ? 1 : 0);
}

static int
ssl_iostream_context_cache_cmp(const struct ssl_iostream_context_cache *c1,
			       const struct ssl_iostream_context_cache *c2)
{
	if (c1->server != c2->server)
		return -1;
	if (!ssl_iostream_application_protocols_equals(c1->application_protocols,
						       c2->application_protocols))
		return -1;
	return ssl_iostream_settings_equals(c1->set, c2->set) ? 0 : -1;
}

static int
ssl_iostream_context_cache_get(const struct ssl_iostream_settings *set,
			       const char *const *application_protocols,
			       bool server,
			       struct ssl_iostream_context **ctx_r,
			       const char **error_r)
{
	struct ssl_iostream_context *ctx;
	struct ssl_iostream_context_cache *cache;
	struct ssl_iostream_context_cache lookup = {
		.server = server,
		.set = set,
		.application_protocols = application_protocols,
	};

	/* The application protocols can be given either via the settings or
	   via the parameter, but not both. */
	i_assert(application_protocols == NULL ||
		 set->application_protocols == NULL);

	if (ssl_iostream_contexts_pool == NULL) {
		ssl_iostream_contexts_pool =
			pool_alloconly_create(MEMPOOL_GROWING"ssl iostream context cache", 1024);
		hash_table_create(&ssl_iostream_contexts,
				  ssl_iostream_contexts_pool, 0,
				  ssl_iostream_context_cache_hash,
				  ssl_iostream_context_cache_cmp);
	}

	ctx = hash_table_lookup(ssl_iostream_contexts, &lookup);
	if (ctx != NULL) {
		ssl_iostream_context_ref(ctx);
		*ctx_r = ctx;
		return 0;
	}

	/* add to cache */
	if (server) {
		if (ssl_iostream_context_init_server(set, &ctx, error_r) < 0)
			return -1;
	} else {
		if (ssl_iostream_context_init_client(set, &ctx, error_r) < 0)
			return -1;
	}
	if (application_protocols != NULL) {
		ssl_iostream_context_set_application_protocols(
			ctx, application_protocols);
	}

	cache = p_new(ssl_iostream_contexts_pool,
		      struct ssl_iostream_context_cache, 1);
	cache->server = server;
	cache->set = set;
	if (application_protocols != NULL) {
		cache->application_protocols =
			p_strarray_dup(ssl_iostream_contexts_pool,
				       application_protocols);
	}
	pool_ref(cache->set->pool);
	hash_table_insert(ssl_iostream_contexts, cache, ctx);

	ssl_iostream_context_ref(ctx);
	*ctx_r = ctx;
	return 1;
}

int ssl_iostream_client_context_cache_get(const struct ssl_iostream_settings *set,
					  const char *const *application_protocols,
					  struct ssl_iostream_context **ctx_r,
					  const char **error_r)
{
	const char *error;
	int ret;

	if ((ret = ssl_iostream_context_cache_get(set, application_protocols,
						  FALSE, ctx_r, &error)) < 0) {
		*error_r = t_strdup_printf(
			"Couldn't initialize SSL client context: %s", error);
		return -1;
	}
	return ret;
}

int ssl_iostream_server_context_cache_get(const struct ssl_iostream_settings *set,
					  const char *const *application_protocols,
					  struct ssl_iostream_context **ctx_r,
					  const char **error_r)
{
	const char *error;
	int ret;

	if ((ret = ssl_iostream_context_cache_get(set, application_protocols,
						  TRUE, ctx_r, &error)) < 0) {
		*error_r = t_strdup_printf(
			"Couldn't initialize SSL server context: %s", error);
		return -1;
	}
	return ret;
}

void ssl_iostream_context_cache_free(void)
{
	struct hash_iterate_context *iter;
	struct ssl_iostream_context_cache *cache;
	struct ssl_iostream_context *ctx;

	if (ssl_iostream_contexts_pool == NULL)
		return;

	iter = hash_table_iterate_init(ssl_iostream_contexts);
	while (hash_table_iterate(iter, ssl_iostream_contexts, &cache, &ctx)) {
		ssl_iostream_context_unref(&ctx);
		settings_free(cache->set);
	}
	hash_table_iterate_deinit(&iter);
	hash_table_destroy(&ssl_iostream_contexts);
	pool_unref(&ssl_iostream_contexts_pool);
}
