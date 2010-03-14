#ifndef PASSDB_CACHE_H
#define PASSDB_CACHE_H

#include "auth-cache.h"

enum passdb_result;
extern struct auth_cache *passdb_cache;

bool passdb_cache_verify_plain(struct auth_request *request, const char *key,
			       const char *password,
			       enum passdb_result *result_r, int use_expired);
bool passdb_cache_lookup_credentials(struct auth_request *request,
				     const char *key, const char **password_r,
				     const char **scheme_r,
				     enum passdb_result *result_r,
				     bool use_expired);

void passdb_cache_init(const struct auth_settings *set);
void passdb_cache_deinit(void);

#endif
