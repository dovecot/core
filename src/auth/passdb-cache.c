/* Copyright (c) 2004-2016 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "strescape.h"
#include "restrict-process-size.h"
#include "auth-request-stats.h"
#include "password-scheme.h"
#include "passdb.h"
#include "passdb-cache.h"

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
	auth_request_log_debug(request, AUTH_SUBSYS_DB, "cache hit: %s", value);
}

static bool
passdb_cache_lookup(struct auth_request *request, const char *key,
		    bool use_expired, struct auth_cache_node **node_r,
		    const char **value_r, bool *neg_expired_r)
{
	struct auth_stats *stats = auth_request_stats_get(request);
	const char *value;
	bool expired;

	/* value = password \t ... */
	value = auth_cache_lookup(passdb_cache, request, key, node_r,
				  &expired, neg_expired_r);
	if (value == NULL || (expired && !use_expired)) {
		stats->auth_cache_miss_count++;
		auth_request_log_debug(request, AUTH_SUBSYS_DB,
				       value == NULL ? "cache miss" :
				       "cache expired");
		return FALSE;
	}
	stats->auth_cache_hit_count++;
	passdb_cache_log_hit(request, value);

	*value_r = value;
	return TRUE;
}

bool passdb_cache_verify_plain(struct auth_request *request, const char *key,
			       const char *password,
			       enum passdb_result *result_r, bool use_expired)
{
	const char *value, *cached_pw, *scheme, *const *list;
	struct auth_cache_node *node;
	int ret;
	bool neg_expired;

	if (passdb_cache == NULL || key == NULL)
		return FALSE;

	if (!passdb_cache_lookup(request, key, use_expired,
				 &node, &value, &neg_expired))
		return FALSE;

	if (*value == '\0') {
		/* negative cache entry */
		auth_request_log_unknown_user(request, AUTH_SUBSYS_DB);
		*result_r = PASSDB_RESULT_USER_UNKNOWN;
		return TRUE;
	}

	list = t_strsplit_tabescaped(value);

	cached_pw = list[0];
	if (*cached_pw == '\0') {
		/* NULL password */
		auth_request_log_info(request, AUTH_SUBSYS_DB,
				      "Cached NULL password access");
		ret = 1;
	} else {
		scheme = password_get_scheme(&cached_pw);
		i_assert(scheme != NULL);

		ret = auth_request_password_verify(request, password, cached_pw,
						   scheme, AUTH_SUBSYS_DB);

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
	bool neg_expired;

	if (passdb_cache == NULL)
		return FALSE;

	if (!passdb_cache_lookup(request, key, use_expired,
				 &node, &value, &neg_expired))
		return FALSE;

	if (*value == '\0') {
		/* negative cache entry */
		*result_r = PASSDB_RESULT_USER_UNKNOWN;
		*password_r = NULL;
		*scheme_r = NULL;
		return TRUE;
	}

	list = t_strsplit_tabescaped(value);
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
