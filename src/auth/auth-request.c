/* Copyright (c) 2002-2010 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "ioloop.h"
#include "buffer.h"
#include "hash.h"
#include "sha1.h"
#include "hex-binary.h"
#include "str.h"
#include "safe-memset.h"
#include "str-sanitize.h"
#include "strescape.h"
#include "var-expand.h"
#include "auth-cache.h"
#include "auth-request.h"
#include "auth-request-handler.h"
#include "auth-client-connection.h"
#include "auth-master-connection.h"
#include "passdb.h"
#include "passdb-blocking.h"
#include "userdb-blocking.h"
#include "passdb-cache.h"
#include "password-scheme.h"

#include <stdlib.h>
#include <sys/stat.h>

#define CACHED_PASSWORD_SCHEME "SHA1"

unsigned int auth_request_state_count[AUTH_REQUEST_STATE_MAX];

static void get_log_prefix(string_t *str, struct auth_request *auth_request,
			   const char *subsystem);

struct auth_request *
auth_request_new(const struct mech_module *mech,
		 mech_callback_t *callback, void *context)
{
	struct auth_request *request;

	request = mech->auth_new();

	request->state = AUTH_REQUEST_STATE_NEW;
	auth_request_state_count[AUTH_REQUEST_STATE_NEW]++;

	request->refcount = 1;
	request->last_access = ioloop_time;

	request->set = global_auth_settings;
	request->mech = mech;
	request->mech_name = mech == NULL ? NULL : mech->mech_name;
	request->callback = callback;
	request->context = context;
	return request;
}

struct auth_request *auth_request_new_dummy(void)
{
	struct auth_request *request;
	pool_t pool;

	pool = pool_alloconly_create("auth_request", 1024);
	request = p_new(pool, struct auth_request, 1);
	request->pool = pool;

	request->state = AUTH_REQUEST_STATE_NEW;
	auth_request_state_count[AUTH_REQUEST_STATE_NEW]++;

	request->refcount = 1;
	request->last_access = ioloop_time;
	request->set = global_auth_settings;
	return request;
}

void auth_request_set_state(struct auth_request *request,
			    enum auth_request_state state)
{
	if (request->state == state)
		return;

	i_assert(auth_request_state_count[request->state] > 0);
	auth_request_state_count[request->state]--;
	auth_request_state_count[state]++;

	request->state = state;
	auth_refresh_proctitle();
}

void auth_request_init(struct auth_request *request)
{
	struct auth *auth;

	auth = auth_request_get_auth(request);
	request->set = auth->set;
	request->passdb = auth->passdbs;
	request->userdb = auth->userdbs;
}

struct auth *auth_request_get_auth(struct auth_request *request)
{
	return auth_find_service(request->service);
}

void auth_request_success(struct auth_request *request,
			  const void *data, size_t data_size)
{
	i_assert(request->state == AUTH_REQUEST_STATE_MECH_CONTINUE);

	if (request->passdb_failure) {
		/* password was valid, but some other check failed. */
		auth_request_fail(request);
		return;
	}

	auth_request_set_state(request, AUTH_REQUEST_STATE_FINISHED);
	request->successful = TRUE;
	auth_request_refresh_last_access(request);
	request->callback(request, AUTH_CLIENT_RESULT_SUCCESS,
			  data, data_size);
}

void auth_request_fail(struct auth_request *request)
{
	i_assert(request->state == AUTH_REQUEST_STATE_MECH_CONTINUE);

	auth_request_set_state(request, AUTH_REQUEST_STATE_FINISHED);
	auth_request_refresh_last_access(request);
	request->callback(request, AUTH_CLIENT_RESULT_FAILURE, NULL, 0);
}

void auth_request_internal_failure(struct auth_request *request)
{
	request->internal_failure = TRUE;
	auth_request_fail(request);
}

void auth_request_ref(struct auth_request *request)
{
	request->refcount++;
}

void auth_request_unref(struct auth_request **_request)
{
	struct auth_request *request = *_request;

	*_request = NULL;
	i_assert(request->refcount > 0);
	if (--request->refcount > 0)
		return;

	auth_request_state_count[request->state]--;
	auth_refresh_proctitle();

	if (request->to_abort != NULL)
		timeout_remove(&request->to_abort);
	if (request->to_penalty != NULL)
		timeout_remove(&request->to_penalty);

	if (request->mech != NULL)
		request->mech->auth_free(request);
	else
		pool_unref(&request->pool);
}

void auth_request_export(struct auth_request *request,
			 struct auth_stream_reply *reply)
{
	auth_stream_reply_add(reply, "user", request->user);
	auth_stream_reply_add(reply, "service", request->service);

        if (request->master_user != NULL) {
		auth_stream_reply_add(reply, "master_user",
				      request->master_user);
	}
	auth_stream_reply_add(reply, "original_username",
			      request->original_username);

	if (request->local_ip.family != 0) {
		auth_stream_reply_add(reply, "lip",
				      net_ip2addr(&request->local_ip));
	}
	if (request->remote_ip.family != 0) {
		auth_stream_reply_add(reply, "rip",
				      net_ip2addr(&request->remote_ip));
	}
	if (request->local_port != 0) {
		auth_stream_reply_add(reply, "lport",
				      dec2str(request->local_port));
	}
	if (request->remote_port != 0) {
		auth_stream_reply_add(reply, "rport",
				      dec2str(request->remote_port));
	}
	if (request->secured)
		auth_stream_reply_add(reply, "secured", "1");
	if (request->skip_password_check)
		auth_stream_reply_add(reply, "skip_password_check", "1");
	if (request->valid_client_cert)
		auth_stream_reply_add(reply, "valid-client-cert", "1");
	if (request->mech_name != NULL)
		auth_stream_reply_add(reply, "mech", request->mech_name);
}

bool auth_request_import(struct auth_request *request,
			 const char *key, const char *value)
{
	if (strcmp(key, "user") == 0)
		request->user = p_strdup(request->pool, value);
	else if (strcmp(key, "master_user") == 0)
		request->master_user = p_strdup(request->pool, value);
	else if (strcmp(key, "original_username") == 0)
		request->original_username = p_strdup(request->pool, value);
	else if (strcmp(key, "cert_username") == 0) {
		if (request->set->ssl_username_from_cert) {
			/* get username from SSL certificate. it overrides
			   the username given by the auth mechanism. */
			request->user = p_strdup(request->pool, value);
			request->cert_username = TRUE;
		}
	} else if (strcmp(key, "service") == 0)
		request->service = p_strdup(request->pool, value);
	else if (strcmp(key, "lip") == 0)
		net_addr2ip(value, &request->local_ip);
	else if (strcmp(key, "rip") == 0)
		net_addr2ip(value, &request->remote_ip);
	else if (strcmp(key, "lport") == 0)
		request->local_port = atoi(value);
	else if (strcmp(key, "rport") == 0)
		request->remote_port = atoi(value);
	else if (strcmp(key, "secured") == 0)
		request->secured = TRUE;
	else if (strcmp(key, "nologin") == 0)
		request->no_login = TRUE;
	else if (strcmp(key, "valid-client-cert") == 0)
		request->valid_client_cert = TRUE;
	else if (strcmp(key, "skip_password_check") == 0) {
		i_assert(request->master_user !=  NULL);
		request->skip_password_check = TRUE;
	} else if (strcmp(key, "mech") == 0)
		request->mech_name = p_strdup(request->pool, value);
	else
		return FALSE;

	return TRUE;
}

void auth_request_initial(struct auth_request *request)
{
	i_assert(request->state == AUTH_REQUEST_STATE_NEW);

	auth_request_set_state(request, AUTH_REQUEST_STATE_MECH_CONTINUE);
	request->mech->auth_initial(request, request->initial_response,
				    request->initial_response_len);
}

void auth_request_continue(struct auth_request *request,
			   const unsigned char *data, size_t data_size)
{
	i_assert(request->state == AUTH_REQUEST_STATE_MECH_CONTINUE);

	auth_request_refresh_last_access(request);
	request->mech->auth_continue(request, data, data_size);
}

static void auth_request_save_cache(struct auth_request *request,
				    enum passdb_result result)
{
	struct passdb_module *passdb = request->passdb->passdb;
	const char *extra_fields, *encoded_password;
	string_t *str;

	switch (result) {
	case PASSDB_RESULT_USER_UNKNOWN:
	case PASSDB_RESULT_PASSWORD_MISMATCH:
	case PASSDB_RESULT_OK:
	case PASSDB_RESULT_SCHEME_NOT_AVAILABLE:
		/* can be cached */
		break;
	case PASSDB_RESULT_USER_DISABLED:
	case PASSDB_RESULT_PASS_EXPIRED:
		/* FIXME: we can't cache this now, or cache lookup would
		   return success. */
		return;
	case PASSDB_RESULT_INTERNAL_FAILURE:
		i_unreached();
	}

	extra_fields = request->extra_fields == NULL ? NULL :
		auth_stream_reply_export(request->extra_fields);

	if (passdb_cache == NULL)
		return;

	if (passdb->cache_key == NULL)
		return;

	if (result < 0) {
		/* lookup failed. */
		if (result == PASSDB_RESULT_USER_UNKNOWN) {
			auth_cache_insert(passdb_cache, request,
					  passdb->cache_key, "", FALSE);
		}
		return;
	}

	if (!request->no_password && request->passdb_password == NULL) {
		/* passdb didn't provide the correct password */
		if (result != PASSDB_RESULT_OK ||
		    request->mech_password == NULL)
			return;

		/* we can still cache valid password lookups though.
		   strdup() it so that mech_password doesn't get
		   cleared too early. */
		if (!password_generate_encoded(request->mech_password,
					       request->user,
					       CACHED_PASSWORD_SCHEME,
					       &encoded_password))
			i_unreached();
		request->passdb_password =
			p_strconcat(request->pool, "{"CACHED_PASSWORD_SCHEME"}",
				    encoded_password, NULL);
	}

	/* save all except the currently given password in cache */
	str = t_str_new(256);
	if (request->passdb_password != NULL) {
		if (*request->passdb_password != '{') {
			/* cached passwords must have a known scheme */
			str_append_c(str, '{');
			str_append(str, passdb->default_pass_scheme);
			str_append_c(str, '}');
		}
		if (strchr(request->passdb_password, '\t') != NULL)
			i_panic("%s: Password contains TAB", request->user);
		if (strchr(request->passdb_password, '\n') != NULL)
			i_panic("%s: Password contains LF", request->user);
		str_append(str, request->passdb_password);
	}

	if (extra_fields != NULL && *extra_fields != '\0') {
		str_append_c(str, '\t');
		str_append(str, extra_fields);
	}
	if (request->extra_cache_fields != NULL) {
		extra_fields =
			auth_stream_reply_export(request->extra_cache_fields);
		if (*extra_fields != '\0') {
			str_append_c(str, '\t');
			str_append(str, extra_fields);
		}
	}
	auth_cache_insert(passdb_cache, request, passdb->cache_key, str_c(str),
			  result == PASSDB_RESULT_OK);
}

static bool auth_request_master_lookup_finish(struct auth_request *request)
{
	if (request->passdb_failure)
		return TRUE;

	/* master login successful. update user and master_user variables. */
	auth_request_log_info(request, "passdb", "Master user logging in as %s",
			      request->requested_login_user);

	request->master_user = request->user;
	request->user = request->requested_login_user;
	request->requested_login_user = NULL;

	request->skip_password_check = TRUE;
	request->passdb_password = NULL;

	if (!request->passdb->set->pass) {
		/* skip the passdb lookup, we're authenticated now. */
		return TRUE;
	}

	/* the authentication continues with passdb lookup for the
	   requested_login_user. */
	request->passdb = auth_request_get_auth(request)->passdbs;
	return FALSE;
}

static bool
auth_request_handle_passdb_callback(enum passdb_result *result,
				    struct auth_request *request)
{
	if (request->passdb_password != NULL) {
		safe_memset(request->passdb_password, 0,
			    strlen(request->passdb_password));
	}

	if (request->destroyed) {
		/* the passdb may have been freed already. this request won't
		   be sent anywhere anyway, so just fail it immediately. */
		*result = PASSDB_RESULT_INTERNAL_FAILURE;
		return TRUE;
	}

	if (request->passdb->set->deny &&
	    *result != PASSDB_RESULT_USER_UNKNOWN) {
		/* deny passdb. we can get through this step only if the
		   lookup returned that user doesn't exist in it. internal
		   errors are fatal here. */
		if (*result != PASSDB_RESULT_INTERNAL_FAILURE) {
			auth_request_log_info(request, "passdb",
					      "User found from deny passdb");
			*result = PASSDB_RESULT_USER_DISABLED;
		}
	} else if (*result == PASSDB_RESULT_OK) {
		/* success */
		if (request->requested_login_user != NULL) {
			/* this was a master user lookup. */
			if (!auth_request_master_lookup_finish(request))
				return FALSE;
		} else {
			if (request->passdb->set->pass) {
				/* this wasn't the final passdb lookup,
				   continue to next passdb */
				request->passdb = request->passdb->next;
				request->passdb_password = NULL;
				return FALSE;
			}
		}
	} else if (*result == PASSDB_RESULT_PASS_EXPIRED) {
		if (request->extra_fields == NULL) {
			request->extra_fields =
				auth_stream_reply_init(request->pool);
		}
	        auth_stream_reply_add(request->extra_fields, "reason",
				      "Password expired");
	} else if (request->passdb->next != NULL &&
		   *result != PASSDB_RESULT_USER_DISABLED) {
		/* try next passdb. */
                request->passdb = request->passdb->next;
		request->passdb_password = NULL;

                if (*result == PASSDB_RESULT_INTERNAL_FAILURE) {
			/* remember that we have had an internal failure. at
			   the end return internal failure if we couldn't
			   successfully login. */
			request->passdb_internal_failure = TRUE;
		}
		if (request->extra_fields != NULL)
			auth_stream_reply_reset(request->extra_fields);

		return FALSE;
	} else if (request->passdb_internal_failure) {
		/* last passdb lookup returned internal failure. it may have
		   had the correct password, so return internal failure
		   instead of plain failure. */
		*result = PASSDB_RESULT_INTERNAL_FAILURE;
	}

	return TRUE;
}

static void
auth_request_verify_plain_callback_finish(enum passdb_result result,
					  struct auth_request *request)
{
	if (!auth_request_handle_passdb_callback(&result, request)) {
		/* try next passdb */
		auth_request_verify_plain(request, request->mech_password,
			request->private_callback.verify_plain);
	} else {
		auth_request_ref(request);
		request->private_callback.verify_plain(result, request);
		safe_memset(request->mech_password, 0,
			    strlen(request->mech_password));
		auth_request_unref(&request);
	}
}

void auth_request_verify_plain_callback(enum passdb_result result,
					struct auth_request *request)
{
	i_assert(request->state == AUTH_REQUEST_STATE_PASSDB);

	auth_request_set_state(request, AUTH_REQUEST_STATE_MECH_CONTINUE);

	if (result != PASSDB_RESULT_INTERNAL_FAILURE)
		auth_request_save_cache(request, result);
	else {
		/* lookup failed. if we're looking here only because the
		   request was expired in cache, fallback to using cached
		   expired record. */
		const char *cache_key = request->passdb->passdb->cache_key;

		if (passdb_cache_verify_plain(request, cache_key,
					      request->mech_password,
					      &result, TRUE)) {
			auth_request_log_info(request, "passdb",
				"Fallbacking to expired data from cache");
		}
	}

	auth_request_verify_plain_callback_finish(result, request);
}

static bool password_has_illegal_chars(const char *password)
{
	for (; *password != '\0'; password++) {
		switch (*password) {
		case '\001':
		case '\t':
		case '\r':
		case '\n':
			/* these characters have a special meaning in internal
			   protocols, make sure the password doesn't
			   accidentally get there unescaped. */
			return TRUE;
		}
	}
	return FALSE;
}

void auth_request_verify_plain(struct auth_request *request,
			       const char *password,
			       verify_plain_callback_t *callback)
{
	struct passdb_module *passdb;
	enum passdb_result result;
	const char *cache_key;

	i_assert(request->state == AUTH_REQUEST_STATE_MECH_CONTINUE);

        if (request->passdb == NULL) {
                /* no masterdbs, master logins not supported */
                i_assert(request->requested_login_user != NULL);
		auth_request_log_info(request, "passdb",
			"Attempted master login with no master passdbs "
			"(trying to log in as user: %s)",
			request->requested_login_user);
		callback(PASSDB_RESULT_USER_UNKNOWN, request);
		return;
	}

	if (password_has_illegal_chars(password)) {
		auth_request_log_info(request, "passdb",
			"Attempted login with password having illegal chars");
		callback(PASSDB_RESULT_USER_UNKNOWN, request);
		return;
	}

        passdb = request->passdb->passdb;
	if (request->mech_password == NULL)
		request->mech_password = p_strdup(request->pool, password);
	else
		i_assert(request->mech_password == password);
	request->private_callback.verify_plain = callback;

	cache_key = passdb_cache == NULL ? NULL : passdb->cache_key;
	if (passdb_cache_verify_plain(request, cache_key, password,
				      &result, FALSE)) {
		auth_request_verify_plain_callback_finish(result, request);
		return;
	}

	auth_request_set_state(request, AUTH_REQUEST_STATE_PASSDB);
	request->credentials_scheme = NULL;

	if (passdb->blocking)
		passdb_blocking_verify_plain(request);
	else {
		passdb->iface.verify_plain(request, password,
					   auth_request_verify_plain_callback);
	}
}

static void
auth_request_lookup_credentials_finish(enum passdb_result result,
				       const unsigned char *credentials,
				       size_t size,
				       struct auth_request *request)
{
	if (!auth_request_handle_passdb_callback(&result, request)) {
		/* try next passdb */
		auth_request_lookup_credentials(request,
			request->credentials_scheme,
                	request->private_callback.lookup_credentials);
	} else {
		if (request->set->debug_passwords &&
		    result == PASSDB_RESULT_OK) {
			auth_request_log_debug(request, "password",
				"Credentials: %s",
				binary_to_hex(credentials, size));
		}
		request->private_callback.
			lookup_credentials(result, credentials, size, request);
	}
}

void auth_request_lookup_credentials_callback(enum passdb_result result,
					      const unsigned char *credentials,
					      size_t size,
					      struct auth_request *request)
{
	const char *cache_cred, *cache_scheme;

	i_assert(request->state == AUTH_REQUEST_STATE_PASSDB);

	auth_request_set_state(request, AUTH_REQUEST_STATE_MECH_CONTINUE);

	if (result != PASSDB_RESULT_INTERNAL_FAILURE)
		auth_request_save_cache(request, result);
	else {
		/* lookup failed. if we're looking here only because the
		   request was expired in cache, fallback to using cached
		   expired record. */
		const char *cache_key = request->passdb->passdb->cache_key;

		if (passdb_cache_lookup_credentials(request, cache_key,
						    &cache_cred, &cache_scheme,
						    &result, TRUE)) {
			auth_request_log_info(request, "passdb",
				"Fallbacking to expired data from cache");
			passdb_handle_credentials(
				result, cache_cred, cache_scheme,
				auth_request_lookup_credentials_finish,
				request);
			return;
		}
	}

	auth_request_lookup_credentials_finish(result, credentials, size,
					       request);
}

void auth_request_lookup_credentials(struct auth_request *request,
				     const char *scheme,
				     lookup_credentials_callback_t *callback)
{
	struct passdb_module *passdb = request->passdb->passdb;
	const char *cache_key, *cache_cred, *cache_scheme;
	enum passdb_result result;

	i_assert(request->state == AUTH_REQUEST_STATE_MECH_CONTINUE);

	request->credentials_scheme = p_strdup(request->pool, scheme);
	request->private_callback.lookup_credentials = callback;

	cache_key = passdb_cache == NULL ? NULL : passdb->cache_key;
	if (cache_key != NULL) {
		if (passdb_cache_lookup_credentials(request, cache_key,
						    &cache_cred, &cache_scheme,
						    &result, FALSE)) {
			passdb_handle_credentials(
				result, cache_cred, cache_scheme,
				auth_request_lookup_credentials_finish,
				request);
			return;
		}
	}

	auth_request_set_state(request, AUTH_REQUEST_STATE_PASSDB);

	if (passdb->iface.lookup_credentials == NULL) {
		/* this passdb doesn't support credentials */
		auth_request_log_debug(request, "password",
			"passdb doesn't support credential lookups");
		auth_request_lookup_credentials_callback(
			PASSDB_RESULT_SCHEME_NOT_AVAILABLE, NULL, 0, request);
	} else if (passdb->blocking) {
		passdb_blocking_lookup_credentials(request);
	} else {
		passdb->iface.lookup_credentials(request,
			auth_request_lookup_credentials_callback);
	}
}

void auth_request_set_credentials(struct auth_request *request,
				  const char *scheme, const char *data,
				  set_credentials_callback_t *callback)
{
	struct passdb_module *passdb = request->passdb->passdb;
	const char *cache_key, *new_credentials;

	cache_key = passdb_cache == NULL ? NULL : passdb->cache_key;
	if (cache_key != NULL)
		auth_cache_remove(passdb_cache, request, cache_key);

	request->private_callback.set_credentials = callback;

	new_credentials = t_strdup_printf("{%s}%s", scheme, data);
	if (passdb->blocking)
		passdb_blocking_set_credentials(request, new_credentials);
	else if (passdb->iface.set_credentials != NULL) {
		passdb->iface.set_credentials(request, new_credentials,
					      callback);
	} else {
		/* this passdb doesn't support credentials update */
		callback(PASSDB_RESULT_INTERNAL_FAILURE, request);
	}
}

static void auth_request_userdb_save_cache(struct auth_request *request,
					   enum userdb_result result)
{
	struct userdb_module *userdb = request->userdb->userdb;
	const char *str;

	if (passdb_cache == NULL || userdb->cache_key == NULL)
		return;

	str = result == USERDB_RESULT_USER_UNKNOWN ? "" :
		auth_stream_reply_export(request->userdb_reply);
	/* last_success has no meaning with userdb */
	auth_cache_insert(passdb_cache, request, userdb->cache_key, str, FALSE);
}

static bool auth_request_lookup_user_cache(struct auth_request *request,
					   const char *key,
					   struct auth_stream_reply **reply_r,
					   enum userdb_result *result_r,
					   bool use_expired)
{
	const char *value;
	struct auth_cache_node *node;
	bool expired, neg_expired;

	value = auth_cache_lookup(passdb_cache, request, key, &node,
				  &expired, &neg_expired);
	if (value == NULL || (expired && !use_expired))
		return FALSE;

	if (*value == '\0') {
		/* negative cache entry */
		*result_r = USERDB_RESULT_USER_UNKNOWN;
		*reply_r = auth_stream_reply_init(request->pool);
		return TRUE;
	}

	*result_r = USERDB_RESULT_OK;
	*reply_r = auth_stream_reply_init(request->pool);
	auth_stream_reply_import(*reply_r, value);
	return TRUE;
}

void auth_request_userdb_callback(enum userdb_result result,
				  struct auth_request *request)
{
	struct userdb_module *userdb = request->userdb->userdb;

	if (request->destroyed) {
		/* the userdb may have been freed already. this request won't
		   be sent anywhere anyway, so just fail it immediately. */
		request->private_callback.
			userdb(USERDB_RESULT_INTERNAL_FAILURE, request);
		return;
	}

	if (result != USERDB_RESULT_OK && request->userdb->next != NULL) {
		/* try next userdb. */
		if (result == USERDB_RESULT_INTERNAL_FAILURE)
			request->userdb_internal_failure = TRUE;

		request->userdb = request->userdb->next;
		auth_request_lookup_user(request,
					 request->private_callback.userdb);
		return;
	}

	if (request->userdb_internal_failure && result != USERDB_RESULT_OK) {
		/* one of the userdb lookups failed. the user might have been
		   in there, so this is an internal failure */
		result = USERDB_RESULT_INTERNAL_FAILURE;
	} else if (result == USERDB_RESULT_USER_UNKNOWN &&
		   request->client_pid != 0) {
		/* this was an actual login attempt, the user should
		   have been found. */
		if (auth_request_get_auth(request)->userdbs->next == NULL) {
			auth_request_log_error(request, "userdb",
				"user not found from userdb %s",
				request->userdb->userdb->iface->name);
		} else {
			auth_request_log_error(request, "userdb",
				"user not found from any userdbs");
		}
	}

	if (request->userdb_lookup_failed) {
		/* no caching */
	} else if (result != USERDB_RESULT_INTERNAL_FAILURE)
		auth_request_userdb_save_cache(request, result);
	else if (passdb_cache != NULL && userdb->cache_key != NULL) {
		/* lookup failed. if we're looking here only because the
		   request was expired in cache, fallback to using cached
		   expired record. */
		const char *cache_key = userdb->cache_key;
		struct auth_stream_reply *reply;

		if (auth_request_lookup_user_cache(request, cache_key, &reply,
						   &result, TRUE)) {
			request->userdb_reply = reply;
			auth_request_log_info(request, "userdb",
				"Fallbacking to expired data from cache");
		}
	}

        request->private_callback.userdb(result, request);
}

void auth_request_lookup_user(struct auth_request *request,
			      userdb_callback_t *callback)
{
	struct userdb_module *userdb = request->userdb->userdb;
	const char *cache_key;

	request->private_callback.userdb = callback;
	request->userdb_lookup = TRUE;

	/* (for now) auth_cache is shared between passdb and userdb */
	cache_key = passdb_cache == NULL ? NULL : userdb->cache_key;
	if (cache_key != NULL) {
		struct auth_stream_reply *reply;
		enum userdb_result result;

		if (auth_request_lookup_user_cache(request, cache_key, &reply,
						   &result, FALSE)) {
			request->userdb_reply = reply;
			request->private_callback.userdb(result, request);
			return;
		}
	}

	if (userdb->blocking)
		userdb_blocking_lookup(request);
	else
		userdb->iface->lookup(request, auth_request_userdb_callback);
}

static char *
auth_request_fix_username(struct auth_request *request, const char *username,
                          const char **error_r)
{
	const struct auth_settings *set = request->set;
	unsigned char *p;
	char *user;

	if (*set->default_realm != '\0' &&
	    strchr(username, '@') == NULL) {
		user = p_strconcat(request->pool, username, "@",
                                   set->default_realm, NULL);
	} else {
		user = p_strdup(request->pool, username);
	}

        for (p = (unsigned char *)user; *p != '\0'; p++) {
		if (set->username_translation_map[*p & 0xff] != 0)
			*p = set->username_translation_map[*p & 0xff];
		if (set->username_chars_map[*p & 0xff] == 0) {
			*error_r = t_strdup_printf(
				"Username contains disallowed character: "
				"0x%02x", *p);
			return NULL;
		}
	}

	if (*set->username_format != '\0') {
		/* username format given, put it through variable expansion.
		   we'll have to temporarily replace request->user to get
		   %u to be the wanted username */
		const struct var_expand_table *table;
		char *old_username;
		string_t *dest;

		old_username = request->user;
		request->user = user;

		dest = t_str_new(256);
		table = auth_request_get_var_expand_table(request, NULL);
		var_expand(dest, set->username_format, table);
		user = p_strdup(request->pool, str_c(dest));

		request->user = old_username;
	}

        return user;
}

bool auth_request_set_username(struct auth_request *request,
			       const char *username, const char **error_r)
{
	const struct auth_settings *set = request->set;
	const char *p, *login_username = NULL;

	if (*set->master_user_separator != '\0' && !request->userdb_lookup) {
		/* check if the username contains a master user */
		p = strchr(username, *set->master_user_separator);
		if (p != NULL) {
			/* it does, set it. */
			login_username = t_strdup_until(username, p);

			if (*login_username == '\0') {
				*error_r = "Empty login username";
				return FALSE;
			}

			/* username is the master user */
			username = p + 1;
		}
	}

	if (request->original_username == NULL) {
		/* the username may change later, but we need to use this
		   username when verifying at least DIGEST-MD5 password. */
		request->original_username = p_strdup(request->pool, username);
	}
	if (request->cert_username) {
		/* cert_username overrides the username given by
		   authentication mechanism. but still do checks and
		   translations to it. */
		username = request->user;
	}

	if (*username == '\0') {
		/* Some PAM plugins go nuts with empty usernames */
		*error_r = "Empty username";
		return FALSE;
	}

        request->user = auth_request_fix_username(request, username, error_r);
	if (request->user == NULL) {
		auth_request_log_debug(request, "auth",
			"Invalid username: %s", str_sanitize(username, 128));
		return FALSE;
	}
	if (request->translated_username == NULL) {
		/* similar to original_username, but after translations */
		request->translated_username = request->user;
	}

	if (login_username != NULL) {
		if (!auth_request_set_login_username(request,
						     login_username,
						     error_r))
			return FALSE;
	}
	return TRUE;
}

bool auth_request_set_login_username(struct auth_request *request,
                                     const char *username,
                                     const char **error_r)
{
        i_assert(*username != '\0');

	if (strcmp(username, request->user) == 0) {
		/* The usernames are the same, we don't really wish to log
		   in as someone else */
		return TRUE;
	}

        /* lookup request->user from masterdb first */
        request->passdb = auth_request_get_auth(request)->masterdbs;

        request->requested_login_user =
                auth_request_fix_username(request, username, error_r);
	return request->requested_login_user != NULL;
}

static void auth_request_validate_networks(struct auth_request *request,
					   const char *networks)
{
	const char *const *net;
	struct ip_addr net_ip;
	unsigned int bits;
	bool found = FALSE;

	if (request->remote_ip.family == 0) {
		/* IP not known */
		auth_request_log_info(request, "passdb",
			"allow_nets check failed: Remote IP not known");
		request->passdb_failure = TRUE;
		return;
	}

	for (net = t_strsplit_spaces(networks, ", "); *net != NULL; net++) {
		auth_request_log_debug(request, "auth",
			"allow_nets: Matching for network %s", *net);

		if (net_parse_range(*net, &net_ip, &bits) < 0) {
			auth_request_log_info(request, "passdb",
				"allow_nets: Invalid network '%s'", *net);
		}

		if (net_is_in_network(&request->remote_ip, &net_ip, bits)) {
			found = TRUE;
			break;
		}
	}

	if (!found) {
		auth_request_log_info(request, "passdb",
			"allow_nets check failed: IP not in allowed networks");
	}
	request->passdb_failure = !found;
}

static void
auth_request_set_password(struct auth_request *request, const char *value,
			  const char *default_scheme, bool noscheme)
{
	if (request->passdb_password != NULL) {
		auth_request_log_error(request,
			request->passdb->passdb->iface.name,
			"Multiple password values not supported");
		return;
	}

	/* if the password starts with '{' it most likely contains
	   also '}'. check it anyway to make sure, because we
	   assert-crash later if it doesn't exist. this could happen
	   if plaintext passwords are used. */
	if (*value == '{' && !noscheme && strchr(value, '}') != NULL)
		request->passdb_password = p_strdup(request->pool, value);
	else {
		i_assert(default_scheme != NULL);
		request->passdb_password =
			p_strdup_printf(request->pool, "{%s}%s",
					default_scheme, value);
	}
}

static void auth_request_set_reply_field(struct auth_request *request,
					 const char *name, const char *value)
{
	if (strcmp(name, "nologin") == 0) {
		/* user can't actually login - don't keep this
		   reply for master */
		request->no_login = TRUE;
		value = NULL;
	} else if (strcmp(name, "proxy") == 0) {
		/* we're proxying authentication for this user. send
		   password back if using plaintext authentication. */
		request->proxy = TRUE;
		value = NULL;
	} else if (strcmp(name, "proxy_maybe") == 0) {
		/* like "proxy", but log in normally if we're proxying to
		   ourself */
		request->proxy = TRUE;
		request->proxy_maybe = TRUE;
		value = NULL;
	}

	if (request->extra_fields == NULL)
		request->extra_fields = auth_stream_reply_init(request->pool);
	auth_stream_reply_add(request->extra_fields, name, value);
}

void auth_request_set_field(struct auth_request *request,
			    const char *name, const char *value,
			    const char *default_scheme)
{
	const char *p, *orig_value;

	i_assert(*name != '\0');
	i_assert(value != NULL);

	if (strcmp(name, "password") == 0) {
		auth_request_set_password(request, value,
					  default_scheme, FALSE);
		return;
	}
	if (strcmp(name, "password_noscheme") == 0) {
		auth_request_set_password(request, value, default_scheme, TRUE);
		return;
	}

	if (strcmp(name, "user") == 0 ||
	    strcmp(name, "username") == 0 || strcmp(name, "domain") == 0) {
		/* update username */
		orig_value = value;
		if (strcmp(name, "username") == 0 &&
		    strchr(value, '@') == NULL &&
		    (p = strchr(request->user, '@')) != NULL) {
			/* preserve the current @domain */
			value = t_strconcat(value, p, NULL);
		} else if (strcmp(name, "domain") == 0) {
			p = strchr(request->user, '@');
			if (p == NULL) {
				/* add the domain */
				value = t_strconcat(request->user, "@",
						    value, NULL);
			} else {
				/* replace the existing domain */
				p = t_strdup_until(request->user, p + 1);
				value = t_strconcat(p, value, NULL);
			}
		}

		if (strcmp(request->user, value) != 0) {
			auth_request_log_debug(request, "auth",
				"username changed %s -> %s",
				request->user, value);
			request->user = p_strdup(request->pool, value);
		}
		/* restore the original value so it gets saved correctly to
		   cache. */
		value = orig_value;
	} else if (strcmp(name, "nodelay") == 0) {
		/* don't delay replying to client of the failure */
		request->no_failure_delay = TRUE;
	} else if (strcmp(name, "nopassword") == 0) {
		/* NULL password - anything goes */
		const char *password = request->passdb_password;

		if (password != NULL) {
			(void)password_get_scheme(&password);
			if (*password != '\0') {
				auth_request_log_error(request,
					request->passdb->passdb->iface.name,
					"nopassword set but password is "
					"non-empty");
				return;
			}
		}
		request->no_password = TRUE;
		request->passdb_password = NULL;
	} else if (strcmp(name, "allow_nets") == 0) {
		auth_request_validate_networks(request, value);
	} else if (strncmp(name, "userdb_", 7) == 0) {
		/* for prefetch userdb */
		if (request->userdb_reply == NULL)
			auth_request_init_userdb_reply(request);
		auth_request_set_userdb_field(request, name + 7, value);
	} else {
		/* these fields are returned to client */
		auth_request_set_reply_field(request, name, value);
		return;
	}

	if ((passdb_cache != NULL &&
	     request->passdb->passdb->cache_key != NULL) || worker) {
		/* we'll need to get this field stored into cache,
		   or we're a worker and we'll need to send this to the main
		   auth process that can store it in the cache. */
		if (request->extra_cache_fields == NULL) {
			request->extra_cache_fields =
				auth_stream_reply_init(request->pool);
		}
		auth_stream_reply_add(request->extra_cache_fields, name, value);
	}
}

void auth_request_set_fields(struct auth_request *request,
			     const char *const *fields,
			     const char *default_scheme)
{
	const char *key, *value;

	for (; *fields != NULL; fields++) {
		if (**fields == '\0')
			continue;

		value = strchr(*fields, '=');
		if (value == NULL) {
			key = *fields;
			value = "";
		} else {
			key = t_strdup_until(*fields, value);
			value++;
		}
		auth_request_set_field(request, key, value, default_scheme);
	}
}

void auth_request_init_userdb_reply(struct auth_request *request)
{
	request->userdb_reply = auth_stream_reply_init(request->pool);
	auth_stream_reply_add(request->userdb_reply, NULL, request->user);
}

static void
auth_request_change_userdb_user(struct auth_request *request, const char *user)
{
	const char *str;

	/* replace the username in userdb_reply if it changed */
	if (strcmp(user, request->user) == 0)
		return;

	str = t_strdup(auth_stream_reply_export(request->userdb_reply));

	/* reset the reply and add the new username */
	auth_request_set_field(request, "user", user, NULL);
	auth_stream_reply_reset(request->userdb_reply);
	auth_stream_reply_add(request->userdb_reply,
			      NULL, request->user);

	/* add the rest */
	str = strchr(str, '\t');
	if (str != NULL)
		auth_stream_reply_import(request->userdb_reply, str + 1);
}

static void auth_request_set_uidgid_file(struct auth_request *request,
					 const char *path_template)
{
	string_t *path;
	struct stat st;

	path = t_str_new(256);
	var_expand(path, path_template,
		   auth_request_get_var_expand_table(request, NULL));
	if (stat(str_c(path), &st) < 0) {
		auth_request_log_error(request, "uidgid_file",
				       "stat(%s) failed: %m", str_c(path));
	} else {
		auth_stream_reply_add(request->userdb_reply,
				      "uid", dec2str(st.st_uid));
		auth_stream_reply_add(request->userdb_reply,
				      "gid", dec2str(st.st_gid));
	}
}

void auth_request_set_userdb_field(struct auth_request *request,
				   const char *name, const char *value)
{
	uid_t uid;
	gid_t gid;

	if (strcmp(name, "uid") == 0) {
		uid = userdb_parse_uid(request, value);
		if (uid == (uid_t)-1) {
			request->userdb_lookup_failed = TRUE;
			return;
		}
		value = dec2str(uid);
	} else if (strcmp(name, "gid") == 0) {
		gid = userdb_parse_gid(request, value);
		if (gid == (gid_t)-1) {
			request->userdb_lookup_failed = TRUE;
			return;
		}
		value = dec2str(gid);
	} else if (strcmp(name, "tempfail") == 0) {
		request->userdb_lookup_failed = TRUE;
		return;
	} else if (strcmp(name, "user") == 0) {
		auth_request_change_userdb_user(request, value);
		return;
	} else if (strcmp(name, "uidgid_file") == 0) {
		auth_request_set_uidgid_file(request, value);
		return;
	} else if (strcmp(name, "userdb_import") == 0) {
		auth_stream_reply_import(request->userdb_reply, value);
		return;
	} else if (strcmp(name, "system_user") == 0) {
		/* FIXME: the system_user is for backwards compatibility */
		name = "system_groups_user";
	}

	auth_stream_reply_add(request->userdb_reply, name, value);
}

void auth_request_set_userdb_field_values(struct auth_request *request,
					  const char *name,
					  const char *const *values)
{
	if (*values == NULL)
		return;

	if (strcmp(name, "uid") == 0) {
		/* there can be only one. use the first one. */
		auth_request_set_userdb_field(request, name, *values);
	} else if (strcmp(name, "gid") == 0) {
		/* convert gids to comma separated list */
		string_t *value;
		gid_t gid;

		value = t_str_new(128);
		for (; *values != NULL; values++) {
			gid = userdb_parse_gid(request, *values);
			if (gid == (gid_t)-1) {
				request->userdb_lookup_failed = TRUE;
				return;
			}

			if (str_len(value) > 0)
				str_append_c(value, ',');
			str_append(value, dec2str(gid));
		}
		auth_stream_reply_add(request->userdb_reply, name,
				      str_c(value));
	} else {
		/* add only one */
		auth_request_set_userdb_field(request, name, *values);
	}
}

static bool auth_request_proxy_is_self(struct auth_request *request)
{
	const char *const *tmp, *host = NULL, *port = NULL, *destuser = NULL;
	struct ip_addr ip;

	tmp = auth_stream_split(request->extra_fields);
	for (; *tmp != NULL; tmp++) {
		if (strncmp(*tmp, "host=", 5) == 0)
			host = *tmp + 5;
		else if (strncmp(*tmp, "port=", 5) == 0)
			port = *tmp + 5;
		if (strncmp(*tmp, "destuser=", 9) == 0)
			destuser = *tmp + 9;
	}

	if (host == NULL || net_addr2ip(host, &ip) < 0) {
		/* broken setup */
		return FALSE;
	}
	if (!net_ip_compare(&ip, &request->local_ip))
		return FALSE;

	if (port != NULL && !str_uint_equals(port, request->local_port))
		return FALSE;
	return destuser == NULL ||
		strcmp(destuser, request->original_username) == 0;
}

void auth_request_proxy_finish(struct auth_request *request, bool success)
{
	if (!request->proxy || request->no_login)
		return;

	if (!success) {
		/* drop all proxy fields */
	} else if (!request->proxy_maybe) {
		/* proxying */
		request->no_login = TRUE;
		return;
	} else if (!auth_request_proxy_is_self(request)) {
		/* proxy destination isn't ourself - proxy */
		auth_stream_reply_remove(request->extra_fields, "proxy_maybe");
		auth_stream_reply_add(request->extra_fields, "proxy", NULL);
		request->no_login = TRUE;
		return;
	} else {
		/* proxying to ourself - log in without proxying by dropping
		   all the proxying fields. */
	}
	auth_stream_reply_remove(request->extra_fields, "proxy");
	auth_stream_reply_remove(request->extra_fields, "proxy_maybe");
	auth_stream_reply_remove(request->extra_fields, "host");
	auth_stream_reply_remove(request->extra_fields, "port");
	auth_stream_reply_remove(request->extra_fields, "destuser");
}

static void log_password_failure(struct auth_request *request,
				 const char *plain_password,
				 const char *crypted_password,
				 const char *scheme, const char *user,
				 const char *subsystem)
{
	static bool scheme_ok = FALSE;
	string_t *str = t_str_new(256);
	const char *working_scheme;

	str_printfa(str, "%s(%s) != '%s'", scheme,
		    plain_password, crypted_password);

	if (!scheme_ok) {
		/* perhaps the scheme is wrong - see if we can find
		   a working one */
		working_scheme = password_scheme_detect(plain_password,
							crypted_password, user);
		if (working_scheme != NULL) {
			str_printfa(str, ", try %s scheme instead",
				    working_scheme);
		}
	}

	auth_request_log_debug(request, subsystem, "%s", str_c(str));
}

void auth_request_log_password_mismatch(struct auth_request *request,
					const char *subsystem)
{
	string_t *str;
	const char *log_type = request->set->verbose_passwords;

	if (strcmp(log_type, "no") == 0) {
		auth_request_log_info(request, subsystem, "Password mismatch");
		return;
	}

	str = t_str_new(128);
	get_log_prefix(str, request, subsystem);
	str_append(str, "Password mismatch ");

	if (strcmp(log_type, "plain") == 0) {
		str_printfa(str, "(given password: %s)",
			    request->mech_password);
	} else if (strcmp(log_type, "sha1") == 0) {
		unsigned char sha1[SHA1_RESULTLEN];

		sha1_get_digest(request->mech_password,
				strlen(request->mech_password), sha1);
		str_printfa(str, "(SHA1 of given password: %s)",
			    binary_to_hex(sha1, sizeof(sha1)));
	} else {
		i_unreached();
	}

	i_info("%s", str_c(str));
}

int auth_request_password_verify(struct auth_request *request,
				 const char *plain_password,
				 const char *crypted_password,
				 const char *scheme, const char *subsystem)
{
	const unsigned char *raw_password;
	size_t raw_password_size;
	int ret;

	if (request->skip_password_check) {
		/* currently this can happen only with master logins */
		i_assert(request->master_user != NULL);
		return 1;
	}

	if (request->passdb->set->deny) {
		/* this is a deny database, we don't care about the password */
		return 0;
	}

	if (request->no_password) {
		auth_request_log_info(request, subsystem, "No password");
		return 1;
	}

	ret = password_decode(crypted_password, scheme,
			      &raw_password, &raw_password_size);
	if (ret <= 0) {
		if (ret < 0) {
			auth_request_log_error(request, subsystem,
				"Password in passdb is not in expected scheme %s",
				scheme);
		} else {
			auth_request_log_error(request, subsystem,
					       "Unknown scheme %s", scheme);
		}
		return -1;
	}

	/* Use original_username since it may be important for some
	   password schemes (eg. digest-md5). Otherwise the username is used
	   only for logging purposes. */
	ret = password_verify(plain_password, request->original_username,
			      scheme, raw_password, raw_password_size);
	i_assert(ret >= 0);
	if (ret == 0) {
		auth_request_log_password_mismatch(request, subsystem);
		if (request->set->debug_passwords) T_BEGIN {
			log_password_failure(request, plain_password,
					     crypted_password, scheme,
					     request->original_username,
					     subsystem);
		} T_END;
	}
	return ret;
}

static const char *
escape_none(const char *string,
	    const struct auth_request *request ATTR_UNUSED)
{
	return string;
}

const char *
auth_request_str_escape(const char *string,
			const struct auth_request *request ATTR_UNUSED)
{
	return str_escape(string);
}

const struct var_expand_table *
auth_request_get_var_expand_table(const struct auth_request *auth_request,
				  auth_request_escape_func_t *escape_func)
{
	static struct var_expand_table static_tab[] = {
		{ 'u', NULL, "user" },
		{ 'n', NULL, "username" },
		{ 'd', NULL, "domain" },
		{ 's', NULL, "service" },
		{ 'h', NULL, "home" },
		{ 'l', NULL, "lip" },
		{ 'r', NULL, "rip" },
		{ 'p', NULL, "pid" },
		{ 'w', NULL, "password" },
		{ '!', NULL, NULL },
		{ 'm', NULL, "mech" },
		{ 'c', NULL, "secured" },
		{ 'a', NULL, "lport" },
		{ 'b', NULL, "rport" },
		{ 'k', NULL, "cert" },
		{ '\0', NULL, "login_user" },
		{ '\0', NULL, "login_username" },
		{ '\0', NULL, "login_domain" },
		{ '\0', NULL, NULL }
	};
	struct var_expand_table *tab;

	if (escape_func == NULL)
		escape_func = escape_none;

	tab = t_malloc(sizeof(static_tab));
	memcpy(tab, static_tab, sizeof(static_tab));

	tab[0].value = escape_func(auth_request->user, auth_request);
	tab[1].value = escape_func(t_strcut(auth_request->user, '@'),
				   auth_request);
	tab[2].value = strchr(auth_request->user, '@');
	if (tab[2].value != NULL)
		tab[2].value = escape_func(tab[2].value+1, auth_request);
	tab[3].value = auth_request->service;
	/* tab[4] = we have no home dir */
	if (auth_request->local_ip.family != 0)
		tab[5].value = net_ip2addr(&auth_request->local_ip);
	if (auth_request->remote_ip.family != 0)
		tab[6].value = net_ip2addr(&auth_request->remote_ip);
	tab[7].value = dec2str(auth_request->client_pid);
	if (auth_request->mech_password != NULL) {
		tab[8].value = escape_func(auth_request->mech_password,
					   auth_request);
	}
	if (auth_request->userdb_lookup) {
		tab[9].value = auth_request->userdb == NULL ? "" :
			dec2str(auth_request->userdb->userdb->id);
	} else {
		tab[9].value = auth_request->passdb == NULL ? "" :
			dec2str(auth_request->passdb->passdb->id);
	}
	tab[10].value = auth_request->mech_name == NULL ? "" :
		auth_request->mech_name;
	tab[11].value = auth_request->secured ? "secured" : "";
	tab[12].value = dec2str(auth_request->local_port);
	tab[13].value = dec2str(auth_request->remote_port);
	tab[14].value = auth_request->valid_client_cert ? "valid" : "";

	if (auth_request->requested_login_user != NULL) {
		const char *login_user = auth_request->requested_login_user;

		tab[15].value = escape_func(login_user, auth_request);
		tab[16].value = escape_func(t_strcut(login_user, '@'),
					    auth_request);
		tab[17].value = strchr(login_user, '@');
		if (tab[17].value != NULL) {
			tab[17].value = escape_func(tab[17].value+1,
						    auth_request);
		}
	}
	return tab;
}

static void get_log_prefix(string_t *str, struct auth_request *auth_request,
			   const char *subsystem)
{
#define MAX_LOG_USERNAME_LEN 64
	const char *ip;

	str_append(str, subsystem);
	str_append_c(str, '(');

	if (auth_request->user == NULL)
		str_append(str, "?");
	else {
		str_sanitize_append(str, auth_request->user,
				    MAX_LOG_USERNAME_LEN);
	}

	ip = net_ip2addr(&auth_request->remote_ip);
	if (ip != NULL) {
		str_append_c(str, ',');
		str_append(str, ip);
	}
	if (auth_request->requested_login_user != NULL)
		str_append(str, ",master");
	str_append(str, "): ");
}

static const char * ATTR_FORMAT(3, 0)
get_log_str(struct auth_request *auth_request, const char *subsystem,
	    const char *format, va_list va)
{
	string_t *str;

	str = t_str_new(128);
	get_log_prefix(str, auth_request, subsystem);
	str_vprintfa(str, format, va);
	return str_c(str);
}

void auth_request_log_debug(struct auth_request *auth_request,
			    const char *subsystem,
			    const char *format, ...)
{
	va_list va;

	if (!auth_request->set->debug)
		return;

	va_start(va, format);
	T_BEGIN {
		i_debug("%s", get_log_str(auth_request, subsystem, format, va));
	} T_END;
	va_end(va);
}

void auth_request_log_info(struct auth_request *auth_request,
			   const char *subsystem,
			   const char *format, ...)
{
	va_list va;

	if (!auth_request->set->verbose)
		return;

	va_start(va, format);
	T_BEGIN {
		i_info("%s", get_log_str(auth_request, subsystem, format, va));
	} T_END;
	va_end(va);
}

void auth_request_log_error(struct auth_request *auth_request,
			    const char *subsystem,
			    const char *format, ...)
{
	va_list va;

	va_start(va, format);
	T_BEGIN {
		i_error("%s", get_log_str(auth_request, subsystem, format, va));
	} T_END;
	va_end(va);
}

void auth_request_refresh_last_access(struct auth_request *request)
{
	request->last_access = ioloop_time;
	if (request->to_abort != NULL)
		timeout_reset(request->to_abort);
}
