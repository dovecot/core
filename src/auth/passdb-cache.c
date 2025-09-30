/* Copyright (c) 2004-2018 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "str.h"
#include "strescape.h"
#include "restrict-process-size.h"
#include "auth-worker-connection.h"
#include "password-scheme.h"
#include "passdb.h"
#include "passdb-cache.h"
#include "passdb-blocking.h"

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
	e_debug(authdb_event(request), "cache hit: %s", value);
}

static bool
passdb_cache_lookup(struct auth_request *request, const char *key,
		    bool use_expired, struct auth_cache_node **node_r,
		    const char **value_r, bool *neg_expired_r)
{
	const char *value;
	bool expired;

	request->passdb_cache_result = AUTH_REQUEST_CACHE_MISS;

	/* value = password \t ... */
	value = auth_cache_lookup(passdb_cache, request, key, node_r,
				  &expired, neg_expired_r);
	if (value == NULL || (expired && !use_expired)) {
		e_debug(authdb_event(request),
			value == NULL ? "cache miss" :
			"cache expired");
		return FALSE;
	}
	passdb_cache_log_hit(request, value);
	request->passdb_cache_result = AUTH_REQUEST_CACHE_HIT;

	*value_r = value;
	return TRUE;
}

static bool
passdb_cache_verify_plain_callback(struct auth_worker_connection *conn ATTR_UNUSED,
				   const char *const *args,
				   void *context)
{
	struct auth_request *request = context;
	enum passdb_result result;

	result = passdb_blocking_auth_worker_reply_parse(request, args);
	if (result != PASSDB_RESULT_OK)
		auth_fields_rollback(request->fields.extra_fields);
	auth_request_verify_plain_callback_finish(result, request);
	auth_request_unref(&request);
	return TRUE;
}

bool passdb_cache_verify_plain(struct auth_request *request, const char *key,
			       const char *password,
			       enum passdb_result *result_r, bool use_expired)
{
	const char *value, *cached_pw, *scheme, *const *list;
	struct auth_cache_node *node;
	enum passdb_result ret;
	bool neg_expired;

	if (passdb_cache == NULL || key == NULL)
		return FALSE;

	if (!passdb_cache_lookup(request, key, use_expired,
				 &node, &value, &neg_expired))
		return FALSE;

	if (*value == '\0') {
		/* negative cache entry */
		auth_request_db_log_unknown_user(request);
		*result_r = PASSDB_RESULT_USER_UNKNOWN;
		auth_request_verify_plain_callback_finish(*result_r, request);
		return TRUE;
	}

	list = t_strsplit_tabescaped(value);

	cached_pw = list[0];
	if (*cached_pw == '\0') {
		/* NULL password */
		e_info(authdb_event(request),
		       "Cached NULL password access");
		ret = PASSDB_RESULT_OK;
	} else if (request->set->cache_verify_password_with_worker) {
		string_t *str;

		str = t_str_new(128);
		str_printfa(str, "PASSW\t%u\t", request->passdb->passdb->id);
		str_append_tabescaped(str, password);
		str_append_c(str, '\t');
		str_append_tabescaped(str, cached_pw);
		str_append_c(str, '\t');
		auth_request_export(request, str);

		e_debug(authdb_event(request), "cache: "
			"validating password on worker");
		auth_request_ref(request);
		/* Save the extra fields already here, and take a snapshot.
		   If verification fails, roll back fields. */
		auth_request_set_fields(request, list + 1, NULL);
		auth_fields_snapshot(request->fields.extra_fields);
		auth_worker_call(request->pool, request->fields.user, str_c(str),
				 passdb_cache_verify_plain_callback, request);
		return TRUE;
	} else {
		scheme = password_get_scheme(&cached_pw);
		i_assert(scheme != NULL);

		ret = auth_request_db_password_verify_log(
			request, password, cached_pw, scheme,
			!(node->last_success || neg_expired));

		if (ret == PASSDB_RESULT_PASSWORD_MISMATCH &&
		    (node->last_success || neg_expired)) {
			/* a) the last authentication was successful. assume
			   that the password was changed and cache is expired.
			   b) negative TTL reached, use it for password
			   mismatches too. */
			node->last_success = FALSE;
			return FALSE;
		}
	}
	node->last_success = ret == PASSDB_RESULT_OK;

	/* save the extra_fields only after we know we're using the
	   cached data */
	auth_request_set_fields(request, list + 1, NULL);

	*result_r = ret;

	auth_request_verify_plain_callback_finish(*result_r, request);
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
	    set->cache_size > (uoff_t)limit) {
		i_warning("auth_cache_size (%"PRIuUOFF_T"M) is greater than "
			  "process VSZ limit (%"PRIuUOFF_T"M)",
			  set->cache_size/1024/1024,
			  (uoff_t)(limit/1024/1024));
	}
	passdb_cache = auth_cache_new(set->cache_size, set->cache_ttl,
				      set->cache_negative_ttl);
}

void passdb_cache_deinit(void)
{
	if (passdb_cache != NULL)
		auth_cache_free(&passdb_cache);
}
