/* Copyright (c) 2004-2013 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "restrict-process-size.h"
#include "password-scheme.h"
#include "passdb.h"
#include "passdb-cache.h"

#include <stdlib.h>

struct auth_cache *passdb_cache = NULL;

static void
passdb_cache_log_hit(struct auth_request *request, const char *value)
{
	const char *p;

	if (!request->set->debug_passwords &&
	    *value != '\0' && *value != '\t') {
		/* hide the password */
		p = strchr(value, '\t');
		value = t_strconcat(PASSWORD_HIDDEN_STR, p, NULL);
	}
	auth_request_log_debug(request, "cache", "hit: %s", value);
}

bool passdb_cache_verify_plain(struct auth_request *request, const char *key,
			       const char *password,
			       enum passdb_result *result_r, int use_expired)
{
	const char *value, *cached_pw, *scheme, *const *list;
	struct auth_cache_node *node;
	int ret;
	bool expired, neg_expired;

	if (passdb_cache == NULL || key == NULL || request->master_user != NULL)
		return FALSE;

	/* value = password \t ... */
	value = auth_cache_lookup(passdb_cache, request, key, &node,
				  &expired, &neg_expired);
	if (value == NULL || (expired && !use_expired)) {
		auth_request_log_debug(request, "cache",
				       value == NULL ? "miss" : "expired");
		return FALSE;
	}
	passdb_cache_log_hit(request, value);

	if (*value == '\0') {
		/* negative cache entry */
		auth_request_log_info(request, "cache", "User unknown");
		*result_r = PASSDB_RESULT_USER_UNKNOWN;
		return TRUE;
	}

	list = t_strsplit_tab(value);

	cached_pw = list[0];
	if (*cached_pw == '\0') {
		/* NULL password */
		auth_request_log_info(request, "cache", "NULL password access");
		ret = 1;
	} else {
		scheme = password_get_scheme(&cached_pw);
		i_assert(scheme != NULL);

		ret = auth_request_password_verify(request, password, cached_pw,
						   scheme, "cache");

		if (ret == 0 && (node->last_success || neg_expired)) {
			/* a) the last authentication was successful. assume
			   that the password was changed and cache is expired.
			   b) negative TTL reached, use it for password
			   mismatches too. */
			node->last_success = FALSE;
			return FALSE;
		}
	}
	node->last_success = ret > 0;

	/* save the extra_fields only after we know we're using the
	   cached data */
	auth_request_set_fields(request, list + 1, NULL);

	*result_r = ret > 0 ? PASSDB_RESULT_OK :
		PASSDB_RESULT_PASSWORD_MISMATCH;
	return TRUE;
}

bool passdb_cache_lookup_credentials(struct auth_request *request,
				     const char *key, const char **password_r,
				     const char **scheme_r,
				     enum passdb_result *result_r,
				     bool use_expired)
{
	const char *value, *const *list;
	struct auth_cache_node *node;
	bool expired, neg_expired;

	if (passdb_cache == NULL || request->master_user != NULL)
		return FALSE;

	value = auth_cache_lookup(passdb_cache, request, key, &node,
				  &expired, &neg_expired);
	if (value == NULL || (expired && !use_expired)) {
		auth_request_log_debug(request, "cache",
				       value == NULL ? "miss" : "expired");
		return FALSE;
	}
	passdb_cache_log_hit(request, value);

	if (*value == '\0') {
		/* negative cache entry */
		*result_r = PASSDB_RESULT_USER_UNKNOWN;
		*password_r = NULL;
		*scheme_r = NULL;
		return TRUE;
	}

	list = t_strsplit_tab(value);
	auth_request_set_fields(request, list + 1, NULL);

	*result_r = PASSDB_RESULT_OK;
	*password_r = *list[0] == '\0' ? NULL : list[0];
	*scheme_r = password_get_scheme(password_r);
	i_assert(*scheme_r != NULL || *password_r == NULL);
	return TRUE;
}

void passdb_cache_init(const struct auth_settings *set)
{
	rlim_t limit;

	if (set->cache_size == 0 || set->cache_ttl == 0)
		return;

	if (restrict_get_process_size(&limit) == 0 &&
	    set->cache_size > limit) {
		i_warning("auth_cache_size (%luM) is higher than "
			  "process VSZ limit (%luM)",
			  (unsigned long)(set->cache_size/1024/1024),
			  (unsigned long)(limit/1024/1024));
	}
	passdb_cache = auth_cache_new(set->cache_size, set->cache_ttl,
				      set->cache_negative_ttl);
}

void passdb_cache_deinit(void)
{
	if (passdb_cache != NULL)
		auth_cache_free(&passdb_cache);
}
