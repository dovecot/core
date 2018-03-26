/* Copyright (c) 2017-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "hash.h"
#include "iostream-ssl-private.h"

struct ssl_iostream_context_cache {
	bool server;
	struct ssl_iostream_settings set;
};

static pool_t ssl_iostream_contexts_pool;
static HASH_TABLE(struct ssl_iostream_context_cache *,
		  struct ssl_iostream_context *) ssl_iostream_contexts;

static unsigned int
ssl_iostream_context_cache_hash(const struct ssl_iostream_context_cache *cache)
{
	unsigned int n, i, g, h = 0;
	const char *const cert[] = { cache->set.cert.cert, cache->set.alt_cert.cert };

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
	return h ^ (cache->server ? 1 : 0);
}

static int
ssl_iostream_context_cache_cmp(const struct ssl_iostream_context_cache *c1,
			       const struct ssl_iostream_context_cache *c2)
{
	if (c1->server != c2->server)
		return -1;
	return ssl_iostream_settings_equals(&c1->set, &c2->set) ? 0 : -1;
}

static int
ssl_iostream_context_cache_get(const struct ssl_iostream_settings *set,
			       bool server,
			       struct ssl_iostream_context **ctx_r,
			       const char **error_r)
{
	struct ssl_iostream_context *ctx;
	struct ssl_iostream_context_cache *cache;
	struct ssl_iostream_context_cache lookup = {
		.server = server,
		.set = *set,
	};

	if (ssl_iostream_contexts_pool == NULL) {
		ssl_iostream_contexts_pool =
			pool_alloconly_create(MEMPOOL_GROWING"ssl iostream context cache", 1024);
		hash_table_create(&ssl_iostream_contexts,
				  ssl_iostream_contexts_pool, 0,
				  ssl_iostream_context_cache_hash,
				  ssl_iostream_context_cache_cmp);
	}
	ssl_iostream_settings_drop_stream_only(&lookup.set);

	ctx = hash_table_lookup(ssl_iostream_contexts, &lookup);
	if (ctx != NULL) {
		ssl_iostream_context_ref(ctx);
		*ctx_r = ctx;
		return 0;
	}

	/* add to cache */
	if (server) {
		if (ssl_iostream_context_init_server(&lookup.set, &ctx, error_r) < 0)
			return -1;
	} else {
		if (ssl_iostream_context_init_client(&lookup.set, &ctx, error_r) < 0)
			return -1;
	}

	cache = p_new(ssl_iostream_contexts_pool,
		      struct ssl_iostream_context_cache, 1);
	cache->server = server;
	ssl_iostream_settings_init_from(ssl_iostream_contexts_pool,
					&cache->set, &lookup.set);
	hash_table_insert(ssl_iostream_contexts, cache, ctx);

	ssl_iostream_context_ref(ctx);
	*ctx_r = ctx;
	return 0;
}

int ssl_iostream_client_context_cache_get(const struct ssl_iostream_settings *set,
					  struct ssl_iostream_context **ctx_r,
					  const char **error_r)
{
	return ssl_iostream_context_cache_get(set, FALSE, ctx_r, error_r);
}

int ssl_iostream_server_context_cache_get(const struct ssl_iostream_settings *set,
					  struct ssl_iostream_context **ctx_r,
					  const char **error_r)
{
	return ssl_iostream_context_cache_get(set, TRUE, ctx_r, error_r);
}

void ssl_iostream_context_cache_free(void)
{
	struct hash_iterate_context *iter;
	struct ssl_iostream_context_cache *lookup;
	struct ssl_iostream_context *ctx;

	if (ssl_iostream_contexts_pool == NULL)
		return;

	iter = hash_table_iterate_init(ssl_iostream_contexts);
	while (hash_table_iterate(iter, ssl_iostream_contexts, &lookup, &ctx))
		ssl_iostream_context_unref(&ctx);
	hash_table_iterate_deinit(&iter);
	hash_table_destroy(&ssl_iostream_contexts);
	pool_unref(&ssl_iostream_contexts_pool);
}
