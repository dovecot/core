#ifndef PASSDB_CACHE_H
#define PASSDB_CACHE_H

#include "auth-cache.h"
#include "passdb.h"

extern struct auth_cache *passdb_cache;

typedef void verify_plain_passdb_callback_t(struct auth_request *request);

void passdb_cache_verify_plain(struct auth_request *request, const char *key,
			       const char *password, bool use_expired,
			       verify_plain_passdb_callback_t *fallback);
bool passdb_cache_lookup_credentials(struct auth_request *request,
				     const char *key, const char **password_r,
				     const char **scheme_r,
				     enum passdb_result *result_r,
				     bool use_expired);

void passdb_cache_init(const struct auth_settings *set);
void passdb_cache_deinit(void);

#endif
