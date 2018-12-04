/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "ioloop.h"
#include "buffer.h"
#include "hash.h"
#include "sha1.h"
#include "hex-binary.h"
#include "str.h"
#include "array.h"
#include "safe-memset.h"
#include "str-sanitize.h"
#include "strescape.h"
#include "var-expand.h"
#include "dns-lookup.h"
#include "auth-cache.h"
#include "auth-request.h"
#include "auth-request-handler.h"
#include "auth-request-stats.h"
#include "auth-client-connection.h"
#include "auth-master-connection.h"
#include "auth-policy.h"
#include "passdb.h"
#include "passdb-blocking.h"
#include "passdb-cache.h"
#include "passdb-template.h"
#include "userdb-blocking.h"
#include "userdb-template.h"
#include "password-scheme.h"
#include "wildcard-match.h"

#include <sys/stat.h>

#define AUTH_SUBSYS_PROXY "proxy"
#define AUTH_DNS_SOCKET_PATH "dns-client"
#define AUTH_DNS_DEFAULT_TIMEOUT_MSECS (1000*10)
#define AUTH_DNS_WARN_MSECS 500
#define AUTH_REQUEST_MAX_DELAY_SECS (60*5)
#define CACHED_PASSWORD_SCHEME "SHA1"

struct auth_request_proxy_dns_lookup_ctx {
	struct auth_request *request;
	auth_request_proxy_cb_t *callback;
	struct dns_lookup *dns_lookup;
};

struct auth_policy_check_ctx {
	enum {
		AUTH_POLICY_CHECK_TYPE_PLAIN,
		AUTH_POLICY_CHECK_TYPE_LOOKUP,
		AUTH_POLICY_CHECK_TYPE_SUCCESS,
	} type;
	struct auth_request *request;

	buffer_t *success_data;

	verify_plain_callback_t *callback_plain;
	lookup_credentials_callback_t *callback_lookup;
};

const char auth_default_subsystems[2];

unsigned int auth_request_state_count[AUTH_REQUEST_STATE_MAX];

static void get_log_prefix(string_t *str, struct auth_request *auth_request,
			   const char *subsystem);
static void
auth_request_userdb_import(struct auth_request *request, const char *args);

static
void auth_request_verify_plain_continue(struct auth_request *request,
					verify_plain_callback_t *callback);
static
void auth_request_lookup_credentials_policy_continue(struct auth_request *request,
						     lookup_credentials_callback_t *callback);
static
void auth_request_policy_check_callback(int result, void *context);

static void auth_request_post_alloc_init(struct auth_request *request, struct event *parent_event)
{
	request->state = AUTH_REQUEST_STATE_NEW;
	auth_request_state_count[AUTH_REQUEST_STATE_NEW]++;
	request->refcount = 1;
	request->last_access = ioloop_time;
	request->session_pid = (pid_t)-1;
	request->set = global_auth_settings;
	request->debug = request->set->debug;
	request->extra_fields = auth_fields_init(request->pool);
	request->event = event_create(parent_event);
	event_set_forced_debug(request->event, request->set->debug);
	event_add_category(request->event, &event_category_auth);
}

struct auth_request *
auth_request_new(const struct mech_module *mech, struct event *parent_event)
{
	struct auth_request *request;

	request = mech->auth_new();
	auth_request_post_alloc_init(request, parent_event);
	request->mech = mech;
	request->mech_name = mech->mech_name;
	return request;
}

struct auth_request *auth_request_new_dummy(void)
{
	struct auth_request *request;
	pool_t pool;

	pool = pool_alloconly_create(MEMPOOL_GROWING"auth_request", 1024);
	request = p_new(pool, struct auth_request, 1);
	request->pool = pool;

	auth_request_post_alloc_init(request, NULL);
	return request;
}

void auth_request_set_state(struct auth_request *request,
			    enum auth_request_state state)
{
	if (request->state == state)
		return;

	i_assert(request->to_penalty == NULL);

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
	/* NOTE: request->debug may already be TRUE here */
	if (request->set->debug)
		request->debug = TRUE;
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

	if (!request->set->policy_check_after_auth) {
		buffer_t buf;
		buffer_create_from_const_data(&buf, "", 0);
		struct auth_policy_check_ctx ctx = {
			.success_data = &buf,
			.request = request,
			.type = AUTH_POLICY_CHECK_TYPE_SUCCESS,
		};
		auth_request_policy_check_callback(0, &ctx);
		return;
	}

	/* perform second policy lookup here */
	struct auth_policy_check_ctx *ctx = p_new(request->pool, struct auth_policy_check_ctx, 1);
	ctx->request = request;
	ctx->success_data = buffer_create_dynamic(request->pool, data_size);
	buffer_append(ctx->success_data, data, data_size);
	 ctx->type = AUTH_POLICY_CHECK_TYPE_SUCCESS;
	auth_policy_check(request, request->mech_password, auth_request_policy_check_callback, ctx);
}

static
void auth_request_success_continue(struct auth_policy_check_ctx *ctx)
{
	struct auth_request *request = ctx->request;
	struct auth_stats *stats;
	i_assert(request->state == AUTH_REQUEST_STATE_MECH_CONTINUE);

	timeout_remove(&request->to_penalty);

	if (request->failed || !request->passdb_success) {
		/* password was valid, but some other check failed. */
		auth_request_fail(request);
		return;
	}

	if (request->delay_until > ioloop_time) {
		unsigned int delay_secs = request->delay_until - ioloop_time;
		request->to_penalty = timeout_add(delay_secs * 1000,
			auth_request_success_continue, ctx);
		return;
	}

	request->successful = TRUE;
	if (ctx->success_data->used > 0 && !request->final_resp_ok) {
		/* we'll need one more SASL round, since client doesn't support
		   the final SASL response */
		auth_request_handler_reply_continue(request,
			ctx->success_data->data, ctx->success_data->used);
		return;
	}

	stats = auth_request_stats_get(request);
	stats->auth_success_count++;
	if (request->master_user != NULL)
		stats->auth_master_success_count++;

	auth_request_set_state(request, AUTH_REQUEST_STATE_FINISHED);
	auth_request_refresh_last_access(request);
	auth_request_handler_reply(request, AUTH_CLIENT_RESULT_SUCCESS,
		ctx->success_data->data, ctx->success_data->used);
}

void auth_request_fail(struct auth_request *request)
{
	struct auth_stats *stats;

	i_assert(request->state == AUTH_REQUEST_STATE_MECH_CONTINUE);

	stats = auth_request_stats_get(request);
	stats->auth_failure_count++;

	auth_request_set_state(request, AUTH_REQUEST_STATE_FINISHED);
	auth_request_refresh_last_access(request);
	auth_request_handler_reply(request, AUTH_CLIENT_RESULT_FAILURE, "", 0);
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

	event_unref(&request->event);
	auth_request_stats_send(request);
	auth_request_state_count[request->state]--;
	auth_refresh_proctitle();

	if (request->mech_password != NULL) {
		safe_memset(request->mech_password, 0,
			    strlen(request->mech_password));
	}

	if (request->dns_lookup_ctx != NULL)
		dns_lookup_abort(&request->dns_lookup_ctx->dns_lookup);
	timeout_remove(&request->to_abort);
	timeout_remove(&request->to_penalty);

	if (request->mech != NULL)
		request->mech->auth_free(request);
	else
		pool_unref(&request->pool);
}

static void
auth_str_add_keyvalue(string_t *dest, const char *key, const char *value)
{
	str_append_c(dest, '\t');
	str_append(dest, key);
	if (value != NULL) {
		str_append_c(dest, '=');
		str_append_tabescaped(dest, value);
	}
}

static void
auth_request_export_fields(string_t *dest, struct auth_fields *auth_fields,
			   const char *prefix)
{
	const ARRAY_TYPE(auth_field) *fields = auth_fields_export(auth_fields);
	const struct auth_field *field;

	array_foreach(fields, field) {
		str_printfa(dest, "\t%s%s", prefix, field->key);
		if (field->value != NULL) {
			str_append_c(dest, '=');
			str_append_tabescaped(dest, field->value);
		}
	}
}

void auth_request_export(struct auth_request *request, string_t *dest)
{
	str_append(dest, "user=");
	str_append_tabescaped(dest, request->user);

	auth_str_add_keyvalue(dest, "service", request->service);

	 if (request->master_user != NULL) {
		auth_str_add_keyvalue(dest, "master-user",
				      request->master_user);
	}
	auth_str_add_keyvalue(dest, "original-username",
			      request->original_username);
	if (request->requested_login_user != NULL) {
		auth_str_add_keyvalue(dest, "requested-login-user",
				      request->requested_login_user);
	}

	if (request->local_ip.family != 0) {
		auth_str_add_keyvalue(dest, "lip",
				      net_ip2addr(&request->local_ip));
	}
	if (request->remote_ip.family != 0) {
		auth_str_add_keyvalue(dest, "rip",
				      net_ip2addr(&request->remote_ip));
	}
	if (request->local_port != 0)
		str_printfa(dest, "\tlport=%u", request->local_port);
	if (request->remote_port != 0)
		str_printfa(dest, "\trport=%u", request->remote_port);
	if (request->real_local_ip.family != 0) {
		auth_str_add_keyvalue(dest, "real_lip",
				      net_ip2addr(&request->real_local_ip));
	}
	if (request->real_remote_ip.family != 0) {
		auth_str_add_keyvalue(dest, "real_rip",
				      net_ip2addr(&request->real_remote_ip));
	}
	if (request->real_local_port != 0)
		str_printfa(dest, "\treal_lport=%u", request->real_local_port);
	if (request->real_remote_port != 0)
		str_printfa(dest, "\treal_rport=%u", request->real_remote_port);
	if (request->local_name != 0) {
		str_append(dest, "\tlocal_name=");
		str_append_tabescaped(dest, request->local_name);
	}
	if (request->session_id != NULL)
		str_printfa(dest, "\tsession=%s", request->session_id);
	if (request->debug)
		str_append(dest, "\tdebug");
	switch(request->secured) {
	case AUTH_REQUEST_SECURED_NONE: break;
	case AUTH_REQUEST_SECURED: str_append(dest, "\tsecured"); break;
	case AUTH_REQUEST_SECURED_TLS: str_append(dest, "\tsecured=tls"); break;
	default: break;
	}
	if (request->skip_password_check)
		str_append(dest, "\tskip-password-check");
	if (request->delayed_credentials != NULL)
		str_append(dest, "\tdelayed-credentials");
	if (request->valid_client_cert)
		str_append(dest, "\tvalid-client-cert");
	if (request->no_penalty)
		str_append(dest, "\tno-penalty");
	if (request->successful)
		str_append(dest, "\tsuccessful");
	if (request->mech_name != NULL)
		auth_str_add_keyvalue(dest, "mech", request->mech_name);
	if (request->client_id != NULL)
		auth_str_add_keyvalue(dest, "client_id", request->client_id);
	/* export passdb extra fields */
	auth_request_export_fields(dest, request->extra_fields, "passdb_");
	/* export any userdb fields */
	if (request->userdb_reply != NULL)
		auth_request_export_fields(dest, request->userdb_reply, "userdb_");
}

bool auth_request_import_info(struct auth_request *request,
			      const char *key, const char *value)
{
	i_assert(value != NULL);

	/* authentication and user lookups may set these */
	if (strcmp(key, "service") == 0)
		request->service = p_strdup(request->pool, value);
	else if (strcmp(key, "lip") == 0) {
		(void)net_addr2ip(value, &request->local_ip);
		if (request->real_local_ip.family == 0)
			request->real_local_ip = request->local_ip;
	} else if (strcmp(key, "rip") == 0) {
		(void)net_addr2ip(value, &request->remote_ip);
		if (request->real_remote_ip.family == 0)
			request->real_remote_ip = request->remote_ip;
	} else if (strcmp(key, "lport") == 0) {
		(void)net_str2port(value, &request->local_port);
		if (request->real_local_port == 0)
			request->real_local_port = request->local_port;
	} else if (strcmp(key, "rport") == 0) {
		(void)net_str2port(value, &request->remote_port);
		if (request->real_remote_port == 0)
			request->real_remote_port = request->remote_port;
	}
	else if (strcmp(key, "real_lip") == 0)
		(void)net_addr2ip(value, &request->real_local_ip);
	else if (strcmp(key, "real_rip") == 0)
		(void)net_addr2ip(value, &request->real_remote_ip);
	else if (strcmp(key, "real_lport") == 0)
		(void)net_str2port(value, &request->real_local_port);
	else if (strcmp(key, "real_rport") == 0)
		(void)net_str2port(value, &request->real_remote_port);
	else if (strcmp(key, "local_name") == 0)
		request->local_name = p_strdup(request->pool, value);
	else if (strcmp(key, "session") == 0)
		request->session_id = p_strdup(request->pool, value);
	else if (strcmp(key, "debug") == 0) {
		request->debug = TRUE;
		event_set_forced_debug(request->event, TRUE);
	} else if (strcmp(key, "client_id") == 0)
		request->client_id = p_strdup(request->pool, value);
	else if (strcmp(key, "forward_fields") == 0) {
		auth_fields_import_prefixed(request->extra_fields,
					    "forward_", value, 0);
		/* make sure the forward_ fields aren't deleted by
		   auth_fields_rollback() if the first passdb lookup fails. */
		auth_fields_snapshot(request->extra_fields);
	} else
		return FALSE;
	/* NOTE: keep in sync with auth_request_export() */
	return TRUE;
}

bool auth_request_import_auth(struct auth_request *request,
			      const char *key, const char *value)
{
	i_assert(value != NULL);

	if (auth_request_import_info(request, key, value))
		return TRUE;

	/* auth client may set these */
	if (strcmp(key, "secured") == 0) {
		if (strcmp(value, "tls") == 0)
			request->secured = AUTH_REQUEST_SECURED_TLS;
		else
			request->secured = AUTH_REQUEST_SECURED;
	}
	else if (strcmp(key, "final-resp-ok") == 0)
		request->final_resp_ok = TRUE;
	else if (strcmp(key, "no-penalty") == 0)
		request->no_penalty = TRUE;
	else if (strcmp(key, "valid-client-cert") == 0)
		request->valid_client_cert = TRUE;
	else if (strcmp(key, "cert_username") == 0) {
		if (request->set->ssl_username_from_cert && *value != '\0') {
			/* get username from SSL certificate. it overrides
			   the username given by the auth mechanism. */
			request->user = p_strdup(request->pool, value);
			request->cert_username = TRUE;
		}
	} else {
		return FALSE;
	}
	return TRUE;
}

bool auth_request_import_master(struct auth_request *request,
				const char *key, const char *value)
{
	pid_t pid;

	i_assert(value != NULL);

	/* master request lookups may set these */
	if (strcmp(key, "session_pid") == 0) {
		if (str_to_pid(value, &pid) == 0)
			request->session_pid = pid;
	} else if (strcmp(key, "request_auth_token") == 0)
		request->request_auth_token = TRUE;
	else
		return FALSE;
	return TRUE;
}

bool auth_request_import(struct auth_request *request,
			 const char *key, const char *value)
{
	i_assert(value != NULL);

	if (auth_request_import_auth(request, key, value))
		return TRUE;

	/* for communication between auth master and worker processes */
	if (strcmp(key, "user") == 0)
		request->user = p_strdup(request->pool, value);
	else if (strcmp(key, "master-user") == 0)
		request->master_user = p_strdup(request->pool, value);
	else if (strcmp(key, "original-username") == 0)
		request->original_username = p_strdup(request->pool, value);
	else if (strcmp(key, "requested-login-user") == 0)
		request->requested_login_user = p_strdup(request->pool, value);
	else if (strcmp(key, "successful") == 0)
		request->successful = TRUE;
	else if (strcmp(key, "skip-password-check") == 0)
		request->skip_password_check = TRUE;
	else if (strcmp(key, "delayed-credentials") == 0) {
		/* just make passdb_handle_credentials() work identically in
		   auth-worker as it does in auth-master. the worker shouldn't
		   care about the actual contents of the credentials. */
		request->delayed_credentials = &uchar_nul;
		request->delayed_credentials_size = 1;
	} else if (strcmp(key, "mech") == 0)
		request->mech_name = p_strdup(request->pool, value);
	else if (str_begins(key, "passdb_"))
		auth_fields_add(request->extra_fields, key+7, value, 0);
	else if (str_begins(key, "userdb_")) {
		if (request->userdb_reply == NULL)
			request->userdb_reply = auth_fields_init(request->pool);
		auth_fields_add(request->userdb_reply, key+7, value, 0);
	} else
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

	if (request->successful) {
		auth_request_success(request, "", 0);
		return;
	}

	auth_request_refresh_last_access(request);
	request->mech->auth_continue(request, data, data_size);
}

static void auth_request_save_cache(struct auth_request *request,
				    enum passdb_result result)
{
	struct auth_passdb *passdb = request->passdb;
	const char *encoded_password;
	string_t *str;
	struct password_generate_params gen_params = {.user = request->user,
						      .rounds = 0 };

	switch (result) {
	case PASSDB_RESULT_USER_UNKNOWN:
	case PASSDB_RESULT_PASSWORD_MISMATCH:
	case PASSDB_RESULT_OK:
	case PASSDB_RESULT_SCHEME_NOT_AVAILABLE:
		/* can be cached */
		break;
	case PASSDB_RESULT_NEXT:
	case PASSDB_RESULT_USER_DISABLED:
	case PASSDB_RESULT_PASS_EXPIRED:
		/* FIXME: we can't cache this now, or cache lookup would
		   return success. */
		return;
	case PASSDB_RESULT_INTERNAL_FAILURE:
		i_unreached();
	}

	if (passdb_cache == NULL || passdb->cache_key == NULL)
		return;

	if (result < 0) {
		/* lookup failed. */
		if (result == PASSDB_RESULT_USER_UNKNOWN) {
			auth_cache_insert(passdb_cache, request,
					  passdb->cache_key, "", FALSE);
		}
		return;
	}

	if (request->passdb_password == NULL &&
	    !auth_fields_exists(request->extra_fields, "nopassword")) {
		/* passdb didn't provide the correct password */
		if (result != PASSDB_RESULT_OK ||
		    request->mech_password == NULL)
			return;

		/* we can still cache valid password lookups though.
		   strdup() it so that mech_password doesn't get
		   cleared too early. */
		if (!password_generate_encoded(request->mech_password,
					       &gen_params,
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
			str_append(str, passdb->passdb->default_pass_scheme);
			str_append_c(str, '}');
		}
		str_append_tabescaped(str, request->passdb_password);
	}

	if (!auth_fields_is_empty(request->extra_fields)) {
		str_append_c(str, '\t');
		/* add only those extra fields to cache that were set by this
		   passdb lookup. the CHANGED flag does this, because we
		   snapshotted the extra_fields before the current passdb
		   lookup. */
		auth_fields_append(request->extra_fields, str,
				   AUTH_FIELD_FLAG_CHANGED,
				   AUTH_FIELD_FLAG_CHANGED);
	}
	auth_cache_insert(passdb_cache, request, passdb->cache_key, str_c(str),
			  result == PASSDB_RESULT_OK);
}

static void auth_request_master_lookup_finish(struct auth_request *request)
{
	if (request->failed)
		return;

	/* master login successful. update user and master_user variables. */
	auth_request_log_info(request, AUTH_SUBSYS_DB,
			      "Master user logging in as %s",
			      request->requested_login_user);

	request->master_user = request->user;
	request->user = request->requested_login_user;
	request->requested_login_user = NULL;
}

static bool
auth_request_mechanism_accepted(const char *const *mechs,
				const struct mech_module *mech)
{
	/* no filter specified, anything goes */
	if (mechs == NULL) return TRUE;
	/* request has no mechanism, see if none is accepted */
	if (mech == NULL)
		return str_array_icase_find(mechs, "none");
	/* check if request mechanism is accepted */
	return str_array_icase_find(mechs, mech->mech_name);
}

/**

Check if username is included in the filter. Logic is that if the username
is not excluded by anything, and is included by something, it will be accepted.
By default, all usernames are included, unless there is a inclusion item, when
username will be excluded if there is no inclusion for it.

Exclusions are denoted with a ! in front of the pattern.
*/
bool auth_request_username_accepted(const char *const *filter, const char *username)
{
	bool have_includes = FALSE;
	bool matched_inc = FALSE;

	for(;*filter != NULL; filter++) {
		/* if filter has ! it means the pattern will be refused */
		bool exclude = (**filter == '!');
		if (!exclude)
			have_includes = TRUE;
		if (wildcard_match(username, (*filter)+(exclude?1:0))) {
			if (exclude) {
				return FALSE;
			} else {
				matched_inc = TRUE;
			}
		}
	}

	return matched_inc || !have_includes;
}

static bool
auth_request_want_skip_passdb(struct auth_request *request,
			      struct auth_passdb *passdb)
{
	/* if mechanism is not supported, skip */
	const char *const *mechs = passdb->passdb->mechanisms;
	const char *const *username_filter = passdb->passdb->username_filter;
	const char *username;

	username = request->user;

	if (!auth_request_mechanism_accepted(mechs, request->mech)) {
		auth_request_log_debug(request,
				       request->mech != NULL ? AUTH_SUBSYS_MECH
							      : "none",
				       "skipping passdb: mechanism filtered");
		return TRUE;
	}

	if (passdb->passdb->username_filter != NULL &&
	    !auth_request_username_accepted(username_filter, username)) {
		auth_request_log_debug(request,
				       request->mech != NULL ? AUTH_SUBSYS_MECH
							      : "none",
				       "skipping passdb: username filtered");
		return TRUE;
	}

	/* skip_password_check basically specifies if authentication is
	   finished */
	bool authenticated = request->skip_password_check;

	switch (passdb->skip) {
	case AUTH_PASSDB_SKIP_NEVER:
		return FALSE;
	case AUTH_PASSDB_SKIP_AUTHENTICATED:
		return authenticated;
	case AUTH_PASSDB_SKIP_UNAUTHENTICATED:
		return !authenticated;
	}
	i_unreached();
}

static bool
auth_request_want_skip_userdb(struct auth_request *request,
			      struct auth_userdb *userdb)
{
	switch (userdb->skip) {
	case AUTH_USERDB_SKIP_NEVER:
		return FALSE;
	case AUTH_USERDB_SKIP_FOUND:
		return request->userdb_success;
	case AUTH_USERDB_SKIP_NOTFOUND:
		return !request->userdb_success;
	}
	i_unreached();
}

static bool
auth_request_handle_passdb_callback(enum passdb_result *result,
				    struct auth_request *request)
{
	struct auth_passdb *next_passdb;
	enum auth_db_rule result_rule;
	bool passdb_continue = FALSE;

	if (request->passdb_password != NULL) {
		safe_memset(request->passdb_password, 0,
			    strlen(request->passdb_password));
	}

	if (request->passdb->set->deny &&
	    *result != PASSDB_RESULT_USER_UNKNOWN) {
		/* deny passdb. we can get through this step only if the
		   lookup returned that user doesn't exist in it. internal
		   errors are fatal here. */
		if (*result != PASSDB_RESULT_INTERNAL_FAILURE) {
			auth_request_log_info(request, AUTH_SUBSYS_DB,
					      "User found from deny passdb");
			*result = PASSDB_RESULT_USER_DISABLED;
		}
		return TRUE;
	}
	if (request->failed) {
		/* The passdb didn't fail, but something inside it failed
		   (e.g. allow_nets mismatch). Make sure we'll fail this
		   lookup, but reset the failure so the next passdb can
		   succeed. */
		if (*result == PASSDB_RESULT_OK)
			*result = PASSDB_RESULT_USER_UNKNOWN;
		request->failed = FALSE;
	}

	/* users that exist but can't log in are special. we don't try to match
	   any of the success/failure rules to them. they'll always fail. */
	switch (*result) {
	case PASSDB_RESULT_USER_DISABLED:
		return TRUE;
	case PASSDB_RESULT_PASS_EXPIRED:
		auth_request_set_field(request, "reason",
					"Password expired", NULL);
		return TRUE;

	case PASSDB_RESULT_OK:
		result_rule = request->passdb->result_success;
		break;
	case PASSDB_RESULT_INTERNAL_FAILURE:
		result_rule = request->passdb->result_internalfail;
		break;
	case PASSDB_RESULT_NEXT:
		auth_request_log_debug(request, AUTH_SUBSYS_DB,
			"Not performing authentication (noauthenticate set)");
		result_rule = AUTH_DB_RULE_CONTINUE;
		break;
	case PASSDB_RESULT_SCHEME_NOT_AVAILABLE:
	case PASSDB_RESULT_USER_UNKNOWN:
	case PASSDB_RESULT_PASSWORD_MISMATCH:
	default:
		result_rule = request->passdb->result_failure;
		break;
	}

	switch (result_rule) {
	case AUTH_DB_RULE_RETURN:
		break;
	case AUTH_DB_RULE_RETURN_OK:
		request->passdb_success = TRUE;
		break;
	case AUTH_DB_RULE_RETURN_FAIL:
		request->passdb_success = FALSE;
		break;
	case AUTH_DB_RULE_CONTINUE:
		passdb_continue = TRUE;
		if (*result == PASSDB_RESULT_OK) {
			/* password was successfully verified. don't bother
			   checking it again. */
			request->skip_password_check = TRUE;
		}
		break;
	case AUTH_DB_RULE_CONTINUE_OK:
		passdb_continue = TRUE;
		request->passdb_success = TRUE;
		/* password was successfully verified. don't bother
		   checking it again. */
		request->skip_password_check = TRUE;
		break;
	case AUTH_DB_RULE_CONTINUE_FAIL:
		passdb_continue = TRUE;
		request->passdb_success = FALSE;
		break;
	}
	/* nopassword check is specific to a single passdb and shouldn't leak
	   to the next one. we already added it to cache. */
	auth_fields_remove(request->extra_fields, "nopassword");
	auth_fields_remove(request->extra_fields, "noauthenticate");

	if (request->requested_login_user != NULL &&
	    *result == PASSDB_RESULT_OK) {
		auth_request_master_lookup_finish(request);
		/* if the passdb lookup continues, it continues with non-master
		   passdbs for the requested_login_user. */
		next_passdb = auth_request_get_auth(request)->passdbs;
	} else {
		next_passdb = request->passdb->next;
	}
	while (next_passdb != NULL &&
		auth_request_want_skip_passdb(request, next_passdb))
		next_passdb = next_passdb->next;

	if (*result == PASSDB_RESULT_OK || *result == PASSDB_RESULT_NEXT) {
		/* this passdb lookup succeeded, preserve its extra fields */
		auth_fields_snapshot(request->extra_fields);
		request->snapshot_have_userdb_prefetch_set =
			request->userdb_prefetch_set;
		if (request->userdb_reply != NULL)
			auth_fields_snapshot(request->userdb_reply);
	} else {
		/* this passdb lookup failed, remove any extra fields it set */
		auth_fields_rollback(request->extra_fields);
		if (request->userdb_reply != NULL) {
			auth_fields_rollback(request->userdb_reply);
			request->userdb_prefetch_set =
				request->snapshot_have_userdb_prefetch_set;
		}
	}

	if (passdb_continue && next_passdb != NULL) {
		/* try next passdb. */
		  request->passdb = next_passdb;
		request->passdb_password = NULL;

		if (*result == PASSDB_RESULT_USER_UNKNOWN) {
			/* remember that we did at least one successful
			   passdb lookup */
			request->passdbs_seen_user_unknown = TRUE;
		} else if (*result == PASSDB_RESULT_INTERNAL_FAILURE) {
			/* remember that we have had an internal failure. at
			   the end return internal failure if we couldn't
			   successfully login. */
			request->passdbs_seen_internal_failure = TRUE;
		}
		return FALSE;
	} else if (*result == PASSDB_RESULT_NEXT) {
		/* admin forgot to put proper passdb last */
		auth_request_log_error(request, AUTH_SUBSYS_DB,
			"Last passdb had noauthenticate field, cannot authenticate user");
		*result = PASSDB_RESULT_INTERNAL_FAILURE;
	} else if (request->passdb_success) {
		/* either this or a previous passdb lookup succeeded. */
		*result = PASSDB_RESULT_OK;
	} else if (request->passdbs_seen_internal_failure) {
		/* last passdb lookup returned internal failure. it may have
		   had the correct password, so return internal failure
		   instead of plain failure. */
		*result = PASSDB_RESULT_INTERNAL_FAILURE;
	}
	return TRUE;
}

void
auth_request_verify_plain_callback_finish(enum passdb_result result,
					  struct auth_request *request)
{
	const char *error;

	if (passdb_template_export(request->passdb->override_fields_tmpl,
				   request, &error) < 0) {
		auth_request_log_error(request, AUTH_SUBSYS_DB,
			"Failed to expand override_fields: %s", error);
		result = PASSDB_RESULT_INTERNAL_FAILURE;
	}
	if (!auth_request_handle_passdb_callback(&result, request)) {
		/* try next passdb */
		auth_request_verify_plain(request, request->mech_password,
			request->private_callback.verify_plain);
	} else {
		auth_request_ref(request);
		request->passdb_result = result;
		request->private_callback.verify_plain(request->passdb_result, request);
		auth_request_unref(&request);
	}
}

void auth_request_verify_plain_callback(enum passdb_result result,
					struct auth_request *request)
{
	struct auth_passdb *passdb = request->passdb;

	i_assert(request->state == AUTH_REQUEST_STATE_PASSDB);

	auth_request_set_state(request, AUTH_REQUEST_STATE_MECH_CONTINUE);

	if (result == PASSDB_RESULT_OK &&
	    auth_fields_exists(request->extra_fields, "noauthenticate"))
		result = PASSDB_RESULT_NEXT;

	if (result != PASSDB_RESULT_INTERNAL_FAILURE)
		auth_request_save_cache(request, result);
	else {
		/* lookup failed. if we're looking here only because the
		   request was expired in cache, fallback to using cached
		   expired record. */
		const char *cache_key = passdb->cache_key;

		auth_request_stats_add_tempfail(request);
		if (passdb_cache_verify_plain(request, cache_key,
					      request->mech_password,
					      &result, TRUE)) {
			auth_request_log_info(request, AUTH_SUBSYS_DB,
				"Falling back to expired data from cache");
			return;
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

static bool auth_request_is_disabled_master_user(struct auth_request *request)
{
	if (request->requested_login_user == NULL ||
	    request->passdb != NULL)
		return FALSE;

	/* no masterdbs, master logins not supported */
	auth_request_log_info(request, AUTH_SUBSYS_MECH,
			      "Attempted master login with no master passdbs "
			      "(trying to log in as user: %s)",
			      request->requested_login_user);
	return TRUE;
}

static
void auth_request_policy_penalty_finish(void *context)
{
	struct auth_policy_check_ctx *ctx = context;

	timeout_remove(&ctx->request->to_penalty);

	i_assert(ctx->request->state == AUTH_REQUEST_STATE_MECH_CONTINUE);

	switch(ctx->type) {
	case AUTH_POLICY_CHECK_TYPE_PLAIN:
		auth_request_verify_plain_continue(ctx->request, ctx->callback_plain);
		return;
	case AUTH_POLICY_CHECK_TYPE_LOOKUP:
		auth_request_lookup_credentials_policy_continue(ctx->request, ctx->callback_lookup);
		return;
	case AUTH_POLICY_CHECK_TYPE_SUCCESS:
		auth_request_success_continue(ctx);
		return;
	default:
		i_unreached();
	}
}

static
void auth_request_policy_check_callback(int result, void *context)
{
	struct auth_policy_check_ctx *ctx = context;
	const char *action;

	ctx->request->policy_processed = TRUE;

	if (result < 0)
		action = "drop connection";
	else if (result == 0)
		action = "continue";
	else
		action = t_strdup_printf("tarpit %d second(s)", result);
	if (result != 0)
		auth_request_log_info(ctx->request, "policy", "Policy check action is %s",
				      action);
	else
		auth_request_log_debug(ctx->request, "policy", "Policy check action is %s",
				       action);
	if (result == -1) {
		/* fail it right here and now */
		auth_request_fail(ctx->request);
	} else if (ctx->type != AUTH_POLICY_CHECK_TYPE_SUCCESS && result > 0 && !ctx->request->no_penalty) {
		ctx->request->to_penalty = timeout_add(result * 1000,
				auth_request_policy_penalty_finish,
				context);
	} else {
		auth_request_policy_penalty_finish(context);
	}
}

void auth_request_verify_plain(struct auth_request *request,
				const char *password,
				verify_plain_callback_t *callback)
{
	struct auth_policy_check_ctx *ctx;

	i_assert(request->state == AUTH_REQUEST_STATE_MECH_CONTINUE);

	if (request->mech_password == NULL)
		request->mech_password = p_strdup(request->pool, password);
	else
		i_assert(request->mech_password == password);
	request->user_changed_by_lookup = FALSE;

	if (request->policy_processed || !request->set->policy_check_before_auth) {
		auth_request_verify_plain_continue(request, callback);
	} else {
		ctx = p_new(request->pool, struct auth_policy_check_ctx, 1);
		ctx->request = request;
		ctx->callback_plain = callback;
		ctx->type = AUTH_POLICY_CHECK_TYPE_PLAIN;
		auth_policy_check(request, request->mech_password, auth_request_policy_check_callback, ctx);
	}
}

static
void auth_request_verify_plain_continue(struct auth_request *request,
					verify_plain_callback_t *callback) {

	struct auth_passdb *passdb;
	enum passdb_result result;
	const char *cache_key, *error;
	const char *password = request->mech_password;

	i_assert(request->state == AUTH_REQUEST_STATE_MECH_CONTINUE);

	if (auth_request_is_disabled_master_user(request)) {
		callback(PASSDB_RESULT_USER_UNKNOWN, request);
		return;
	}

	if (password_has_illegal_chars(password)) {
		auth_request_log_info(request, AUTH_SUBSYS_DB,
			"Attempted login with password having illegal chars");
		callback(PASSDB_RESULT_USER_UNKNOWN, request);
		return;
	}

	passdb = request->passdb;

	while (passdb != NULL && auth_request_want_skip_passdb(request, passdb))
		passdb = passdb->next;

	request->passdb = passdb;

	if (passdb == NULL) {
		auth_request_log_error(request,
			request->mech != NULL ? AUTH_SUBSYS_MECH : "none",
			"All password databases were skipped");
		callback(PASSDB_RESULT_INTERNAL_FAILURE, request);
		return;
	}

	request->private_callback.verify_plain = callback;

	cache_key = passdb_cache == NULL ? NULL : passdb->cache_key;
	if (passdb_cache_verify_plain(request, cache_key, password,
				      &result, FALSE)) {
		return;
	}

	auth_request_set_state(request, AUTH_REQUEST_STATE_PASSDB);
	request->credentials_scheme = NULL;

	if (passdb->passdb->iface.verify_plain == NULL) {
		/* we're deinitializing and just want to get rid of this
		   request */
		auth_request_verify_plain_callback(
			PASSDB_RESULT_INTERNAL_FAILURE, request);
	} else if (passdb->passdb->blocking) {
		passdb_blocking_verify_plain(request);
	} else if (passdb_template_export(passdb->default_fields_tmpl,
					  request, &error) < 0) {
		auth_request_log_error(request, AUTH_SUBSYS_DB,
			"Failed to expand default_fields: %s", error);
		auth_request_verify_plain_callback(
			PASSDB_RESULT_INTERNAL_FAILURE, request);
	} else {
		passdb->passdb->iface.verify_plain(request, password,
					   auth_request_verify_plain_callback);
	}
}

static void
auth_request_lookup_credentials_finish(enum passdb_result result,
					const unsigned char *credentials,
					size_t size,
					struct auth_request *request)
{
	const char *error;

	if (passdb_template_export(request->passdb->override_fields_tmpl,
				   request, &error) < 0) {
		auth_request_log_error(request, AUTH_SUBSYS_DB,
			"Failed to expand override_fields: %s", error);
		result = PASSDB_RESULT_INTERNAL_FAILURE;
	}
	if (!auth_request_handle_passdb_callback(&result, request)) {
		/* try next passdb */
		if (request->skip_password_check &&
		    request->delayed_credentials == NULL && size > 0) {
			/* passdb continue* rule after a successful lookup.
			   remember these credentials and use them later on. */
			unsigned char *dup;

			dup = p_malloc(request->pool, size);
			memcpy(dup, credentials, size);
			request->delayed_credentials = dup;
			request->delayed_credentials_size = size;
		}
		auth_request_lookup_credentials(request,
			request->credentials_scheme,
		  	request->private_callback.lookup_credentials);
	} else {
		if (request->delayed_credentials != NULL && size == 0) {
			/* we did multiple passdb lookups, but the last one
			   didn't provide any credentials (e.g. just wanted to
			   add some extra fields). so use the first passdb's
			   credentials instead. */
			credentials = request->delayed_credentials;
			size = request->delayed_credentials_size;
		}
		if (request->set->debug_passwords &&
		    result == PASSDB_RESULT_OK) {
			auth_request_log_debug(request, AUTH_SUBSYS_DB,
				"Credentials: %s",
				binary_to_hex(credentials, size));
		}
		if (result == PASSDB_RESULT_SCHEME_NOT_AVAILABLE &&
		    request->passdbs_seen_user_unknown) {
			/* one of the passdbs accepted the scheme,
			   but the user was unknown there */
			result = PASSDB_RESULT_USER_UNKNOWN;
		}
		request->passdb_result = result;
		request->private_callback.
			lookup_credentials(result, credentials, size, request);
	}
}

void auth_request_lookup_credentials_callback(enum passdb_result result,
					      const unsigned char *credentials,
					      size_t size,
					      struct auth_request *request)
{
	struct auth_passdb *passdb = request->passdb;
	const char *cache_cred, *cache_scheme;

	i_assert(request->state == AUTH_REQUEST_STATE_PASSDB);

	auth_request_set_state(request, AUTH_REQUEST_STATE_MECH_CONTINUE);

	if (result == PASSDB_RESULT_OK &&
	    auth_fields_exists(request->extra_fields, "noauthenticate"))
		result = PASSDB_RESULT_NEXT;

	if (result != PASSDB_RESULT_INTERNAL_FAILURE)
		auth_request_save_cache(request, result);
	else {
		/* lookup failed. if we're looking here only because the
		   request was expired in cache, fallback to using cached
		   expired record. */
		const char *cache_key = passdb->cache_key;

		auth_request_stats_add_tempfail(request);
		if (passdb_cache_lookup_credentials(request, cache_key,
						    &cache_cred, &cache_scheme,
						    &result, TRUE)) {
			auth_request_log_info(request, AUTH_SUBSYS_DB,
				"Falling back to expired data from cache");
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
	struct auth_policy_check_ctx *ctx;

	i_assert(request->state == AUTH_REQUEST_STATE_MECH_CONTINUE);

	if (request->credentials_scheme == NULL)
		request->credentials_scheme = p_strdup(request->pool, scheme);
	request->user_changed_by_lookup = FALSE;

	if (request->policy_processed || !request->set->policy_check_before_auth)
		auth_request_lookup_credentials_policy_continue(request, callback);
	else {
		ctx = p_new(request->pool, struct auth_policy_check_ctx, 1);
		ctx->request = request;
		ctx->callback_lookup = callback;
		ctx->type = AUTH_POLICY_CHECK_TYPE_LOOKUP;
		auth_policy_check(request, ctx->request->mech_password, auth_request_policy_check_callback, ctx);
	}
}

static
void auth_request_lookup_credentials_policy_continue(struct auth_request *request,
						     lookup_credentials_callback_t *callback)
{
	struct auth_passdb *passdb;
	const char *cache_key, *cache_cred, *cache_scheme, *error;
	enum passdb_result result;

	i_assert(request->state == AUTH_REQUEST_STATE_MECH_CONTINUE);
	if (auth_request_is_disabled_master_user(request)) {
		callback(PASSDB_RESULT_USER_UNKNOWN, NULL, 0, request);
		return;
	}
	passdb = request->passdb;
	while (passdb != NULL && auth_request_want_skip_passdb(request, passdb))
		passdb = passdb->next;
	request->passdb = passdb;

	if (passdb == NULL) {
		auth_request_log_error(request,
			request->mech != NULL ? AUTH_SUBSYS_MECH : "none",
			"All password databases were skipped");
		callback(PASSDB_RESULT_INTERNAL_FAILURE, NULL, 0, request);
		return;
	}

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

	if (passdb->passdb->iface.lookup_credentials == NULL) {
		/* this passdb doesn't support credentials */
		auth_request_log_debug(request, AUTH_SUBSYS_DB,
			"passdb doesn't support credential lookups");
		auth_request_lookup_credentials_callback(
					PASSDB_RESULT_SCHEME_NOT_AVAILABLE,
					uchar_empty_ptr, 0, request);
	} else if (passdb->passdb->blocking) {
		passdb_blocking_lookup_credentials(request);
	} else if (passdb_template_export(passdb->default_fields_tmpl,
					  request, &error) < 0) {
		auth_request_log_error(request, AUTH_SUBSYS_DB,
			"Failed to expand default_fields: %s", error);
		auth_request_lookup_credentials_callback(
					PASSDB_RESULT_INTERNAL_FAILURE,
					uchar_empty_ptr, 0, request);
	} else {
		passdb->passdb->iface.lookup_credentials(request,
			auth_request_lookup_credentials_callback);
	}
}

void auth_request_set_credentials(struct auth_request *request,
				  const char *scheme, const char *data,
				  set_credentials_callback_t *callback)
{
	struct auth_passdb *passdb = request->passdb;
	const char *cache_key, *new_credentials;

	cache_key = passdb_cache == NULL ? NULL : passdb->cache_key;
	if (cache_key != NULL)
		auth_cache_remove(passdb_cache, request, cache_key);

	request->private_callback.set_credentials = callback;

	new_credentials = t_strdup_printf("{%s}%s", scheme, data);
	if (passdb->passdb->blocking)
		passdb_blocking_set_credentials(request, new_credentials);
	else if (passdb->passdb->iface.set_credentials != NULL) {
		passdb->passdb->iface.set_credentials(request, new_credentials,
						      callback);
	} else {
		/* this passdb doesn't support credentials update */
		callback(FALSE, request);
	}
}

static void auth_request_userdb_save_cache(struct auth_request *request,
					   enum userdb_result result)
{
	struct auth_userdb *userdb = request->userdb;
	string_t *str;
	const char *cache_value;

	if (passdb_cache == NULL || userdb->cache_key == NULL)
		return;

	if (result == USERDB_RESULT_USER_UNKNOWN)
		cache_value = "";
	else {
		str = t_str_new(128);
		auth_fields_append(request->userdb_reply, str,
				   AUTH_FIELD_FLAG_CHANGED,
				   AUTH_FIELD_FLAG_CHANGED);
		if (request->user_changed_by_lookup) {
			/* username was changed by passdb or userdb */
			if (str_len(str) > 0)
				str_append_c(str, '\t');
			str_append(str, "user=");
			str_append_tabescaped(str, request->user);
		}
		if (str_len(str) == 0) {
			/* no userdb fields. but we can't save an empty string,
			   since that means "user unknown". */
			str_append(str, AUTH_REQUEST_USER_KEY_IGNORE);
		}
		cache_value = str_c(str);
	}
	/* last_success has no meaning with userdb */
	auth_cache_insert(passdb_cache, request, userdb->cache_key,
			  cache_value, FALSE);
}

static bool auth_request_lookup_user_cache(struct auth_request *request,
					   const char *key,
					   enum userdb_result *result_r,
					   bool use_expired)
{
	struct auth_stats *stats = auth_request_stats_get(request);
	const char *value;
	struct auth_cache_node *node;
	bool expired, neg_expired;

	value = auth_cache_lookup(passdb_cache, request, key, &node,
				  &expired, &neg_expired);
	if (value == NULL || (expired && !use_expired)) {
		stats->auth_cache_miss_count++;
		auth_request_log_debug(request, AUTH_SUBSYS_DB,
					value == NULL ? "userdb cache miss" :
					"userdb cache expired");
		return FALSE;
	}
	stats->auth_cache_hit_count++;
	auth_request_log_debug(request, AUTH_SUBSYS_DB,
				"userdb cache hit: %s", value);

	if (*value == '\0') {
		/* negative cache entry */
		*result_r = USERDB_RESULT_USER_UNKNOWN;
		request->userdb_reply = auth_fields_init(request->pool);
		return TRUE;
	}

	/* We want to preserve any userdb fields set by the earlier passdb
	   lookup, so initialize userdb_reply only if it doesn't exist.
	   Don't use auth_request_init_userdb_reply(), because the entire
	   userdb part of the result comes from the cache so we don't want to
	   initialize it with default_fields. */
	if (request->userdb_reply == NULL)
		request->userdb_reply = auth_fields_init(request->pool);
	auth_request_userdb_import(request, value);
	*result_r = USERDB_RESULT_OK;
	return TRUE;
}

void auth_request_userdb_callback(enum userdb_result result,
				  struct auth_request *request)
{
	struct auth_userdb *userdb = request->userdb;
	struct auth_userdb *next_userdb;
	enum auth_db_rule result_rule;
	const char *error;
	bool userdb_continue = FALSE;

	switch (result) {
	case USERDB_RESULT_OK:
		result_rule = userdb->result_success;
		break;
	case USERDB_RESULT_INTERNAL_FAILURE:
		auth_request_stats_add_tempfail(request);
		result_rule = userdb->result_internalfail;
		break;
	case USERDB_RESULT_USER_UNKNOWN:
	default:
		result_rule = userdb->result_failure;
		break;
	}

	switch (result_rule) {
	case AUTH_DB_RULE_RETURN:
		break;
	case AUTH_DB_RULE_RETURN_OK:
		request->userdb_success = TRUE;
		break;
	case AUTH_DB_RULE_RETURN_FAIL:
		request->userdb_success = FALSE;
		break;
	case AUTH_DB_RULE_CONTINUE:
		userdb_continue = TRUE;
		break;
	case AUTH_DB_RULE_CONTINUE_OK:
		userdb_continue = TRUE;
		request->userdb_success = TRUE;
		break;
	case AUTH_DB_RULE_CONTINUE_FAIL:
		userdb_continue = TRUE;
		request->userdb_success = FALSE;
		break;
	}

	next_userdb = userdb->next;
	while (next_userdb != NULL &&
		auth_request_want_skip_userdb(request, next_userdb))
		next_userdb = next_userdb->next;

	if (userdb_continue && next_userdb != NULL) {
		/* try next userdb. */
		if (result == USERDB_RESULT_INTERNAL_FAILURE)
			request->userdbs_seen_internal_failure = TRUE;

		if (result == USERDB_RESULT_OK) {
			/* this userdb lookup succeeded, preserve its extra
			   fields */
			if (userdb_template_export(userdb->override_fields_tmpl,
						   request, &error) < 0) {
				auth_request_log_error(request, AUTH_SUBSYS_DB,
					"Failed to expand override_fields: %s", error);
				request->private_callback.userdb(
					USERDB_RESULT_INTERNAL_FAILURE, request);
				return;
			}
			auth_fields_snapshot(request->userdb_reply);
		} else {
			/* this userdb lookup failed, remove any extra fields
			   it set */
			auth_fields_rollback(request->userdb_reply);
		}
		request->user_changed_by_lookup = FALSE;

		request->userdb = next_userdb;
		auth_request_lookup_user(request,
					 request->private_callback.userdb);
		return;
	}

	if (request->userdb_success) {
		if (userdb_template_export(userdb->override_fields_tmpl,
					   request, &error) < 0) {
			auth_request_log_error(request, AUTH_SUBSYS_DB,
				"Failed to expand override_fields: %s", error);
			result = USERDB_RESULT_INTERNAL_FAILURE;
		} else {
			result = USERDB_RESULT_OK;
		}
	} else if (request->userdbs_seen_internal_failure ||
		   result == USERDB_RESULT_INTERNAL_FAILURE) {
		/* one of the userdb lookups failed. the user might have been
		   in there, so this is an internal failure */
		result = USERDB_RESULT_INTERNAL_FAILURE;
	} else if (request->client_pid != 0) {
		/* this was an actual login attempt, the user should
		   have been found. */
		if (auth_request_get_auth(request)->userdbs->next == NULL) {
			auth_request_log_error(request, AUTH_SUBSYS_DB,
				"user not found from userdb");
		} else {
			auth_request_log_error(request, AUTH_SUBSYS_MECH,
				"user not found from any userdbs");
		}
		result = USERDB_RESULT_USER_UNKNOWN;
	} else {
		result = USERDB_RESULT_USER_UNKNOWN;
	}

	if (request->userdb_lookup_tempfailed) {
		/* no caching */
	} else if (result != USERDB_RESULT_INTERNAL_FAILURE) {
		if (!request->userdb_result_from_cache)
			auth_request_userdb_save_cache(request, result);
	} else if (passdb_cache != NULL && userdb->cache_key != NULL) {
		/* lookup failed. if we're looking here only because the
		   request was expired in cache, fallback to using cached
		   expired record. */
		const char *cache_key = userdb->cache_key;

		if (auth_request_lookup_user_cache(request, cache_key,
						   &result, TRUE)) {
			auth_request_log_info(request, AUTH_SUBSYS_DB,
				"Falling back to expired data from cache");
		}
	}

	 request->private_callback.userdb(result, request);
}

void auth_request_lookup_user(struct auth_request *request,
			      userdb_callback_t *callback)
{
	struct auth_userdb *userdb = request->userdb;
	const char *cache_key, *error;

	request->private_callback.userdb = callback;
	request->user_changed_by_lookup = FALSE;
	request->userdb_lookup = TRUE;
	request->userdb_result_from_cache = FALSE;
	if (request->userdb_reply == NULL)
		auth_request_init_userdb_reply(request);
	else {
		/* we still want to set default_fields. these override any
		   existing fields set by previous userdbs (because if that is
		   unwanted, ":protected" can be used). */
		if (userdb_template_export(userdb->default_fields_tmpl,
					   request, &error) < 0) {
			auth_request_log_error(request, AUTH_SUBSYS_DB,
				"Failed to expand default_fields: %s", error);
			auth_request_userdb_callback(
				USERDB_RESULT_INTERNAL_FAILURE, request);
			return;
		}
	}

	/* (for now) auth_cache is shared between passdb and userdb */
	cache_key = passdb_cache == NULL ? NULL : userdb->cache_key;
	if (cache_key != NULL) {
		enum userdb_result result;

		if (auth_request_lookup_user_cache(request, cache_key,
						   &result, FALSE)) {
			request->userdb_result_from_cache = TRUE;
			auth_request_userdb_callback(result, request);
			return;
		}
	}

	if (userdb->userdb->iface->lookup == NULL) {
		/* we are deinitializing */
		auth_request_userdb_callback(USERDB_RESULT_INTERNAL_FAILURE,
					     request);
	} else if (userdb->userdb->blocking)
		userdb_blocking_lookup(request);
	else
		userdb->userdb->iface->lookup(request, auth_request_userdb_callback);
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
				"Username character disallowed by auth_username_chars: "
				"0x%02x (username: %s)", *p,
				str_sanitize(username, 128));
			return NULL;
		}
	}

	if (*set->username_format != '\0') {
		/* username format given, put it through variable expansion.
		   we'll have to temporarily replace request->user to get
		   %u to be the wanted username */
		const char *error;
		char *old_username;
		string_t *dest;

		old_username = request->user;
		request->user = user;

		dest = t_str_new(256);
		if (auth_request_var_expand(dest, set->username_format,
					    request, NULL, &error) <= 0) {
			*error_r = t_strdup_printf(
				"Failed to expand username_format=%s: %s",
				set->username_format, error);
		}
		user = p_strdup(request->pool, str_c(dest));

		request->user = old_username;
	}

	if (user[0] == '\0') {
		/* Some PAM plugins go nuts with empty usernames */
		*error_r = "Empty username";
		return NULL;
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

	 request->user = auth_request_fix_username(request, username, error_r);
	if (request->user == NULL)
		return FALSE;
	if (request->translated_username == NULL) {
		/* similar to original_username, but after translations */
		request->translated_username = request->user;
	}
	request->user_changed_by_lookup = TRUE;

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
	struct auth_passdb *master_passdb;

	if (username[0] == '\0') {
		*error_r = "Master user login attempted to use empty login username";
		return FALSE;
	}

	if (strcmp(username, request->user) == 0) {
		/* The usernames are the same, we don't really wish to log
		   in as someone else */
		return TRUE;
	}

	 /* lookup request->user from masterdb first */
	master_passdb = auth_request_get_auth(request)->masterdbs;
	if (master_passdb == NULL) {
		*error_r = "Master user login attempted without master passdbs";
		return FALSE;
	}
	request->passdb = master_passdb;

	request->requested_login_user =
		auth_request_fix_username(request, username, error_r);
	if (request->requested_login_user == NULL)
		return FALSE;

	auth_request_log_debug(request, AUTH_SUBSYS_DB,
				"Master user lookup for login: %s",
				request->requested_login_user);
	return TRUE;
}

static void
auth_request_validate_networks(struct auth_request *request,
				const char *name, const char *networks,
				const struct ip_addr *remote_ip)
{
	const char *const *net;
	struct ip_addr net_ip;
	unsigned int bits;
	bool found = FALSE;

	for (net = t_strsplit_spaces(networks, ", "); *net != NULL; net++) {
		auth_request_log_debug(request, AUTH_SUBSYS_DB,
			"%s: Matching for network %s", name, *net);

		if (strcmp(*net, "local") == 0) {
			if (remote_ip->family == 0) {
				found = TRUE;
				break;
			}
		} else if (net_parse_range(*net, &net_ip, &bits) < 0) {
			auth_request_log_info(request, AUTH_SUBSYS_DB,
				"%s: Invalid network '%s'", name, *net);
		} else if (remote_ip->family != 0 &&
			   net_is_in_network(remote_ip, &net_ip, bits)) {
			found = TRUE;
			break;
		}
	}

	if (found)
		;
	else if (remote_ip->family == 0) {
		auth_request_log_info(request, AUTH_SUBSYS_DB,
			"%s check failed: Remote IP not known and 'local' missing", name);
	} else {
		auth_request_log_info(request, AUTH_SUBSYS_DB,
			"%s check failed: IP %s not in allowed networks",
			name, net_ip2addr(remote_ip));
	}
	if (!found)
		request->failed = TRUE;
}

static void
auth_request_set_password(struct auth_request *request, const char *value,
			  const char *default_scheme, bool noscheme)
{
	if (request->passdb_password != NULL) {
		auth_request_log_error(request, AUTH_SUBSYS_DB,
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

static const char *
get_updated_username(const char *old_username,
		     const char *name, const char *value)
{
	const char *p;

	if (strcmp(name, "user") == 0) {
		/* replace the whole username */
		return value;
	}

	p = strchr(old_username, '@');
	if (strcmp(name, "username") == 0) {
		if (strchr(value, '@') != NULL)
			return value;

		/* preserve the current @domain */
		return t_strconcat(value, p, NULL);
	}

	if (strcmp(name, "domain") == 0) {
		if (p == NULL) {
			/* add the domain */
			return t_strconcat(old_username, "@", value, NULL);
		} else {
			/* replace the existing domain */
			p = t_strdup_until(old_username, p + 1);
			return t_strconcat(p, value, NULL);
		}
	}
	return NULL;
}

static bool
auth_request_try_update_username(struct auth_request *request,
				 const char *name, const char *value)
{
	const char *new_value;

	new_value = get_updated_username(request->user, name, value);
	if (new_value == NULL)
		return FALSE;
	if (new_value[0] == '\0') {
		auth_request_log_error(request, AUTH_SUBSYS_DB,
			"username attempted to be changed to empty");
		request->failed = TRUE;
		return TRUE;
	}

	if (strcmp(request->user, new_value) != 0) {
		auth_request_log_debug(request, AUTH_SUBSYS_DB,
					"username changed %s -> %s",
					request->user, new_value);
		request->user = p_strdup(request->pool, new_value);
		request->user_changed_by_lookup = TRUE;
	}
	return TRUE;
}

static void
auth_request_passdb_import(struct auth_request *request, const char *args,
			   const char *key_prefix, const char *default_scheme)
{
	const char *const *arg, *field;

	for (arg = t_strsplit(args, "\t"); *arg != NULL; arg++) {
		field = t_strconcat(key_prefix, *arg, NULL);
		auth_request_set_field_keyvalue(request, field, default_scheme);
	}
}

void auth_request_set_field(struct auth_request *request,
			    const char *name, const char *value,
			    const char *default_scheme)
{
	size_t name_len = strlen(name);

	i_assert(*name != '\0');
	i_assert(value != NULL);

	i_assert(request->passdb != NULL);

	if (name_len > 10 && strcmp(name+name_len-10, ":protected") == 0) {
		/* set this field only if it hasn't been set before */
		name = t_strndup(name, name_len-10);
		if (auth_fields_exists(request->extra_fields, name))
			return;
	} else if (name_len > 7 && strcmp(name+name_len-7, ":remove") == 0) {
		/* remove this field entirely */
		name = t_strndup(name, name_len-7);
		auth_fields_remove(request->extra_fields, name);
		return;
	}

	if (strcmp(name, "password") == 0) {
		auth_request_set_password(request, value,
					  default_scheme, FALSE);
		return;
	}
	if (strcmp(name, "password_noscheme") == 0) {
		auth_request_set_password(request, value, default_scheme, TRUE);
		return;
	}

	if (auth_request_try_update_username(request, name, value)) {
		/* don't change the original value so it gets saved correctly
		   to cache. */
	} else if (strcmp(name, "login_user") == 0) {
		request->requested_login_user = p_strdup(request->pool, value);
	} else if (strcmp(name, "allow_nets") == 0) {
		auth_request_validate_networks(request, name, value, &request->remote_ip);
	} else if (strcmp(name, "fail") == 0) {
		request->failed = TRUE;
	} else if (strcmp(name, "delay_until") == 0) {
		time_t timestamp;
		unsigned int extra_secs = 0;
		const char *p;

		p = strchr(value, '+');
		if (p != NULL) {
			value = t_strdup_until(value, p++);
			if (str_to_uint(p, &extra_secs) < 0) {
				auth_request_log_error(request, AUTH_SUBSYS_DB,
					"Invalid delay_until randomness number '%s'", p);
				request->failed = TRUE;
			} else {
				extra_secs = i_rand_limit(extra_secs);
			}
		}
		if (str_to_time(value, &timestamp) < 0) {
			auth_request_log_error(request, AUTH_SUBSYS_DB,
				"Invalid delay_until timestamp '%s'", value);
			request->failed = TRUE;
		} else if (timestamp <= ioloop_time) {
			/* no more delays */
		} else if (timestamp - ioloop_time > AUTH_REQUEST_MAX_DELAY_SECS) {
			auth_request_log_error(request, AUTH_SUBSYS_DB,
				"delay_until timestamp %s is too much in the future, failing", value);
			request->failed = TRUE;
		} else {
			/* add randomness, but not too much of it */
			timestamp += extra_secs;
			if (timestamp - ioloop_time > AUTH_REQUEST_MAX_DELAY_SECS)
				timestamp = ioloop_time + AUTH_REQUEST_MAX_DELAY_SECS;
			request->delay_until = timestamp;
		}
	} else if (strcmp(name, "allow_real_nets") == 0) {
		auth_request_validate_networks(request, name, value, &request->real_remote_ip);
	} else if (str_begins(name, "userdb_")) {
		/* for prefetch userdb */
		request->userdb_prefetch_set = TRUE;
		if (request->userdb_reply == NULL)
			auth_request_init_userdb_reply(request);
		if (strcmp(name, "userdb_userdb_import") == 0) {
			/* we can't put the whole userdb_userdb_import
			   value to extra_cache_fields or it doesn't work
			   properly. so handle this explicitly. */
			auth_request_passdb_import(request, value,
						   "userdb_", default_scheme);
			return;
		}
		auth_request_set_userdb_field(request, name + 7, value);
	} else if (strcmp(name, "noauthenticate") == 0) {
		/* add "nopassword" also so that passdbs won't try to verify
		   the password. */
		auth_fields_add(request->extra_fields, name, value, 0);
		auth_fields_add(request->extra_fields, "nopassword", NULL, 0);
	} else if (strcmp(name, "nopassword") == 0) {
		/* NULL password - anything goes */
		const char *password = request->passdb_password;

		if (password != NULL &&
		    !auth_fields_exists(request->extra_fields, "noauthenticate")) {
			(void)password_get_scheme(&password);
			if (*password != '\0') {
				auth_request_log_error(request, AUTH_SUBSYS_DB,
					"nopassword set but password is "
					"non-empty");
				return;
			}
		}
		request->passdb_password = NULL;
		auth_fields_add(request->extra_fields, name, value, 0);
		return;
	} else if (strcmp(name, "passdb_import") == 0) {
		auth_request_passdb_import(request, value, "", default_scheme);
		return;
	} else {
		/* these fields are returned to client */
		auth_fields_add(request->extra_fields, name, value, 0);
		return;
	}

	/* add the field unconditionally to extra_fields. this is required if
	   a) auth cache is used, b) if we're a worker and we'll need to send
	   this to the main auth process that can store it in the cache,
	   c) for easily checking :protected fields' existence. */
	auth_fields_add(request->extra_fields, name, value,
			AUTH_FIELD_FLAG_HIDDEN);
}

void auth_request_set_null_field(struct auth_request *request, const char *name)
{
	if (str_begins(name, "userdb_")) {
		/* make sure userdb prefetch is used even if all the fields
		   were returned as NULL. */
		request->userdb_prefetch_set = TRUE;
	}
}

void auth_request_set_field_keyvalue(struct auth_request *request,
				     const char *field,
				     const char *default_scheme)
{
	const char *key, *value;

	value = strchr(field, '=');
	if (value == NULL) {
		key = field;
		value = "";
	} else {
		key = t_strdup_until(field, value);
		value++;
	}
	auth_request_set_field(request, key, value, default_scheme);
}

void auth_request_set_fields(struct auth_request *request,
			     const char *const *fields,
			     const char *default_scheme)
{
	for (; *fields != NULL; fields++) {
		if (**fields == '\0')
			continue;
		auth_request_set_field_keyvalue(request, *fields, default_scheme);
	}
}

void auth_request_init_userdb_reply(struct auth_request *request)
{
	const char *error;

	request->userdb_reply = auth_fields_init(request->pool);
	if (userdb_template_export(request->userdb->default_fields_tmpl,
				   request, &error) < 0) {
		auth_request_log_error(request, AUTH_SUBSYS_DB,
			"Failed to expand default_fields: %s", error);
	}
}

static void auth_request_set_uidgid_file(struct auth_request *request,
					 const char *path_template)
{
	string_t *path;
	struct stat st;
	const char *error;

	path = t_str_new(256);
	if (auth_request_var_expand(path, path_template, request,
				    NULL, &error) <= 0) {
		auth_request_log_error(request, AUTH_SUBSYS_DB,
			"Failed to expand uidgid_file=%s: %s", path_template, error);
		request->userdb_lookup_tempfailed = TRUE;
	} else if (stat(str_c(path), &st) < 0) {
		auth_request_log_error(request, AUTH_SUBSYS_DB,
					"stat(%s) failed: %m", str_c(path));
		request->userdb_lookup_tempfailed = TRUE;
	} else {
		auth_fields_add(request->userdb_reply,
				"uid", dec2str(st.st_uid), 0);
		auth_fields_add(request->userdb_reply,
				"gid", dec2str(st.st_gid), 0);
	}
}

static void
auth_request_userdb_import(struct auth_request *request, const char *args)
{
	const char *key, *value, *const *arg;

	for (arg = t_strsplit(args, "\t"); *arg != NULL; arg++) {
		value = strchr(*arg, '=');
		if (value == NULL) {
			key = *arg;
			value = "";
		} else {
			key = t_strdup_until(*arg, value);
			value++;
		}
		auth_request_set_userdb_field(request, key, value);
	}
}

void auth_request_set_userdb_field(struct auth_request *request,
				   const char *name, const char *value)
{
	size_t name_len = strlen(name);
	uid_t uid;
	gid_t gid;

	i_assert(value != NULL);

	if (name_len > 10 && strcmp(name+name_len-10, ":protected") == 0) {
		/* set this field only if it hasn't been set before */
		name = t_strndup(name, name_len-10);
		if (auth_fields_exists(request->userdb_reply, name))
			return;
	} else if (name_len > 7 && strcmp(name+name_len-7, ":remove") == 0) {
		/* remove this field entirely */
		name = t_strndup(name, name_len-7);
		auth_fields_remove(request->userdb_reply, name);
		return;
	}

	if (strcmp(name, "uid") == 0) {
		uid = userdb_parse_uid(request, value);
		if (uid == (uid_t)-1) {
			request->userdb_lookup_tempfailed = TRUE;
			return;
		}
		value = dec2str(uid);
	} else if (strcmp(name, "gid") == 0) {
		gid = userdb_parse_gid(request, value);
		if (gid == (gid_t)-1) {
			request->userdb_lookup_tempfailed = TRUE;
			return;
		}
		value = dec2str(gid);
	} else if (strcmp(name, "tempfail") == 0) {
		request->userdb_lookup_tempfailed = TRUE;
		return;
	} else if (auth_request_try_update_username(request, name, value)) {
		return;
	} else if (strcmp(name, "uidgid_file") == 0) {
		auth_request_set_uidgid_file(request, value);
		return;
	} else if (strcmp(name, "userdb_import") == 0) {
		auth_request_userdb_import(request, value);
		return;
	} else if (strcmp(name, "system_user") == 0) {
		/* FIXME: the system_user is for backwards compatibility */
		static bool warned = FALSE;
		if (!warned) {
			i_warning("userdb: Replace system_user with system_groups_user");
			warned = TRUE;
		}
		name = "system_groups_user";
	} else if (strcmp(name, AUTH_REQUEST_USER_KEY_IGNORE) == 0) {
		return;
	}

	auth_fields_add(request->userdb_reply, name, value, 0);
}

void auth_request_set_userdb_field_values(struct auth_request *request,
					  const char *name,
					  const char *const *values)
{
	if (*values == NULL)
		return;

	if (strcmp(name, "gid") == 0) {
		/* convert gids to comma separated list */
		string_t *value;
		gid_t gid;

		value = t_str_new(128);
		for (; *values != NULL; values++) {
			gid = userdb_parse_gid(request, *values);
			if (gid == (gid_t)-1) {
				request->userdb_lookup_tempfailed = TRUE;
				return;
			}

			if (str_len(value) > 0)
				str_append_c(value, ',');
			str_append(value, dec2str(gid));
		}
		auth_fields_add(request->userdb_reply, name, str_c(value), 0);
	} else {
		/* add only one */
		if (values[1] != NULL) {
			auth_request_log_warning(request, AUTH_SUBSYS_DB,
				"Multiple values found for '%s', "
				"using value '%s'", name, *values);
		}
		auth_request_set_userdb_field(request, name, *values);
	}
}

static bool auth_request_proxy_is_self(struct auth_request *request)
{
	const char *port = NULL;

	/* check if the port is the same */
	port = auth_fields_find(request->extra_fields, "port");
	if (port != NULL && !str_uint_equals(port, request->local_port))
		return FALSE;
	/* don't check destuser. in some systems destuser is intentionally
	   changed to proxied connections, but that shouldn't affect the
	   proxying decision.

	   it's unlikely any systems would actually want to proxy a connection
	   to itself only to change the username, since it can already be done
	   without proxying by changing the "user" field. */
	return TRUE;
}

static bool
auth_request_proxy_ip_is_self(struct auth_request *request,
			      const struct ip_addr *ip)
{
	unsigned int i;

	if (net_ip_compare(ip, &request->real_local_ip))
		return TRUE;

	for (i = 0; request->set->proxy_self_ips[i].family != 0; i++) {
		if (net_ip_compare(ip, &request->set->proxy_self_ips[i]))
			return TRUE;
	}
	return FALSE;
}

static void
auth_request_proxy_finish_ip(struct auth_request *request,
			     bool proxy_host_is_self)
{
	if (!auth_fields_exists(request->extra_fields, "proxy_maybe")) {
		/* proxying */
	} else if (!proxy_host_is_self ||
		   !auth_request_proxy_is_self(request)) {
		/* proxy destination isn't ourself - proxy */
		auth_fields_remove(request->extra_fields, "proxy_maybe");
		auth_fields_add(request->extra_fields, "proxy", NULL, 0);
	} else {
		/* proxying to ourself - log in without proxying by dropping
		   all the proxying fields. */
		bool proxy_always = auth_fields_exists(request->extra_fields,
							"proxy_always");

		auth_request_proxy_finish_failure(request);
		if (proxy_always) {
			/* setup where "self" refers to the local director
			   cluster, while "non-self" refers to remote clusters.

			   we've matched self here, so add proxy field and
			   let director fill the host. */
			auth_fields_add(request->extra_fields,
					"proxy", NULL, 0);
		}
	}
}

static void
auth_request_proxy_dns_callback(const struct dns_lookup_result *result,
				struct auth_request_proxy_dns_lookup_ctx *ctx)
{
	struct auth_request *request = ctx->request;
	const char *host;
	unsigned int i;
	bool proxy_host_is_self;

	request->dns_lookup_ctx = NULL;
	ctx->dns_lookup = NULL;

	host = auth_fields_find(request->extra_fields, "host");
	i_assert(host != NULL);

	if (result->ret != 0) {
		auth_request_log_error(request, AUTH_SUBSYS_PROXY,
			"DNS lookup for %s failed: %s", host, result->error);
		request->internal_failure = TRUE;
		auth_request_proxy_finish_failure(request);
	} else {
		if (result->msecs > AUTH_DNS_WARN_MSECS) {
			auth_request_log_warning(request, AUTH_SUBSYS_PROXY,
				"DNS lookup for %s took %u.%03u s",
				host, result->msecs/1000, result->msecs % 1000);
		}
		auth_fields_add(request->extra_fields, "hostip",
				net_ip2addr(&result->ips[0]), 0);
		proxy_host_is_self = FALSE;
		for (i = 0; i < result->ips_count; i++) {
			if (auth_request_proxy_ip_is_self(request,
							  &result->ips[i])) {
				proxy_host_is_self = TRUE;
				break;
			}
		}
		auth_request_proxy_finish_ip(request, proxy_host_is_self);
	}
	if (ctx->callback != NULL)
		ctx->callback(result->ret == 0, request);
	auth_request_unref(&request);
}

static int auth_request_proxy_host_lookup(struct auth_request *request,
					  const char *host,
					  auth_request_proxy_cb_t *callback)
{
	struct auth_request_proxy_dns_lookup_ctx *ctx;
	struct dns_lookup_settings dns_set;
	const char *value;
	unsigned int secs;

	/* need to do dns lookup for the host */
	i_zero(&dns_set);
	dns_set.dns_client_socket_path = AUTH_DNS_SOCKET_PATH;
	dns_set.timeout_msecs = AUTH_DNS_DEFAULT_TIMEOUT_MSECS;
	value = auth_fields_find(request->extra_fields, "proxy_timeout");
	if (value != NULL) {
		if (str_to_uint(value, &secs) < 0) {
			auth_request_log_error(request, AUTH_SUBSYS_PROXY,
				"Invalid proxy_timeout value: %s", value);
		} else {
			dns_set.timeout_msecs = secs*1000;
		}
	}

	ctx = p_new(request->pool, struct auth_request_proxy_dns_lookup_ctx, 1);
	ctx->request = request;
	auth_request_ref(request);
	request->dns_lookup_ctx = ctx;

	if (dns_lookup(host, &dns_set, auth_request_proxy_dns_callback, ctx,
			&ctx->dns_lookup) < 0) {
		/* failed early */
		return -1;
	}
	ctx->callback = callback;
	return 0;
}

int auth_request_proxy_finish(struct auth_request *request,
			      auth_request_proxy_cb_t *callback)
{
	const char *host, *hostip;
	struct ip_addr ip;
	bool proxy_host_is_self;

	if (request->auth_only)
		return 1;
	if (!auth_fields_exists(request->extra_fields, "proxy") &&
	    !auth_fields_exists(request->extra_fields, "proxy_maybe"))
		return 1;

	host = auth_fields_find(request->extra_fields, "host");
	if (host == NULL) {
		/* director can set the host. give it access to lip and lport
		   so it can also perform proxy_maybe internally */
		proxy_host_is_self = FALSE;
		if (request->local_ip.family != 0) {
			auth_fields_add(request->extra_fields, "lip",
					net_ip2addr(&request->local_ip), 0);
		}
		if (request->local_port != 0) {
			auth_fields_add(request->extra_fields, "lport",
					dec2str(request->local_port), 0);
		}
	} else if (net_addr2ip(host, &ip) == 0) {
		proxy_host_is_self =
			auth_request_proxy_ip_is_self(request, &ip);
	} else {
		hostip = auth_fields_find(request->extra_fields, "hostip");
		if (hostip != NULL && net_addr2ip(hostip, &ip) < 0) {
			auth_request_log_error(request, AUTH_SUBSYS_PROXY,
				"Invalid hostip in passdb: %s", hostip);
			return -1;
		}
		if (hostip == NULL) {
			/* asynchronous host lookup */
			return auth_request_proxy_host_lookup(request, host, callback);
		}
		proxy_host_is_self =
			auth_request_proxy_ip_is_self(request, &ip);
	}

	auth_request_proxy_finish_ip(request, proxy_host_is_self);
	return 1;
}

void auth_request_proxy_finish_failure(struct auth_request *request)
{
	/* drop all proxying fields */
	auth_fields_remove(request->extra_fields, "proxy");
	auth_fields_remove(request->extra_fields, "proxy_maybe");
	auth_fields_remove(request->extra_fields, "proxy_always");
	auth_fields_remove(request->extra_fields, "host");
	auth_fields_remove(request->extra_fields, "port");
	auth_fields_remove(request->extra_fields, "destuser");
}

static void log_password_failure(struct auth_request *request,
				 const char *plain_password,
				 const char *crypted_password,
				 const char *scheme,
				 const struct password_generate_params *params,
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
							crypted_password, params);
		if (working_scheme != NULL) {
			str_printfa(str, ", try %s scheme instead",
				    working_scheme);
		}
	}

	auth_request_log_debug(request, subsystem, "%s", str_c(str));
}

static void
auth_request_append_password(struct auth_request *request, string_t *str)
{
	const char *p, *log_type = request->set->verbose_passwords;
	unsigned int max_len = 1024;

	if (request->mech_password == NULL)
		return;

	p = strchr(log_type, ':');
	if (p != NULL) {
		if (str_to_uint(p+1, &max_len) < 0)
			i_unreached();
		log_type = t_strdup_until(log_type, p);
	}

	if (strcmp(log_type, "plain") == 0) {
		str_printfa(str, "(given password: %s)",
			    t_strndup(request->mech_password, max_len));
	} else if (strcmp(log_type, "sha1") == 0) {
		unsigned char sha1[SHA1_RESULTLEN];

		sha1_get_digest(request->mech_password,
				strlen(request->mech_password), sha1);
		str_printfa(str, "(SHA1 of given password: %s)",
			    t_strndup(binary_to_hex(sha1, sizeof(sha1)),
				      max_len));
	} else {
		i_unreached();
	}
}

void auth_request_log_password_mismatch(struct auth_request *request,
					const char *subsystem)
{
	auth_request_log_login_failure(request, subsystem, AUTH_LOG_MSG_PASSWORD_MISMATCH);
}

void auth_request_log_unknown_user(struct auth_request *request,
				   const char *subsystem)
{
	auth_request_log_login_failure(request, subsystem, "unknown user");
}

void auth_request_log_login_failure(struct auth_request *request,
				    const char *subsystem,
				    const char *message)
{
	string_t *str;

	if (strcmp(request->set->verbose_passwords, "no") == 0) {
		auth_request_log_info(request, subsystem, "%s", message);
		return;
	}
	str = t_str_new(128);
	get_log_prefix(str, request, subsystem);
	str_append(str, message);
	str_append(str, " ");

	auth_request_append_password(request, str);

	if (request->userdb_lookup) {
		if (request->userdb->next != NULL)
			str_append(str, " - trying the next userdb");
	} else {
		if (request->passdb->next != NULL)
			str_append(str, " - trying the next passdb");
	}
	i_info("%s", str_c(str));
}

int auth_request_password_verify(struct auth_request *request,
				 const char *plain_password,
				 const char *crypted_password,
				 const char *scheme, const char *subsystem)
{
	return auth_request_password_verify_log(request, plain_password,
			crypted_password, scheme, subsystem, TRUE);
}

int auth_request_password_verify_log(struct auth_request *request,
				 const char *plain_password,
				 const char *crypted_password,
				 const char *scheme, const char *subsystem,
				 bool log_password_mismatch)
{
	const unsigned char *raw_password;
	size_t raw_password_size;
	const char *error;
	int ret;
	struct password_generate_params gen_params = {.user = request->original_username,
						      .rounds = 0};

	if (request->skip_password_check) {
		/* passdb continue* rule after a successful authentication */
		return 1;
	}

	if (request->passdb->set->deny) {
		/* this is a deny database, we don't care about the password */
		return 0;
	}

	if (auth_fields_exists(request->extra_fields, "nopassword")) {
		auth_request_log_debug(request, subsystem,
					"Allowing any password");
		return 1;
	}

	ret = password_decode(crypted_password, scheme,
			      &raw_password, &raw_password_size, &error);
	if (ret <= 0) {
		if (ret < 0) {
			auth_request_log_error(request, subsystem,
				"Password data is not valid for scheme %s: %s",
				scheme, error);
		} else {
			auth_request_log_error(request, subsystem,
						"Unknown scheme %s", scheme);
		}
		return -1;
	}

	/* Use original_username since it may be important for some
	   password schemes (eg. digest-md5). Otherwise the username is used
	   only for logging purposes. */
	ret = password_verify(plain_password, &gen_params,
			      scheme, raw_password, raw_password_size, &error);
	if (ret < 0) {
		const char *password_str = request->set->debug_passwords ?
			t_strdup_printf(" '%s'", crypted_password) : "";
		auth_request_log_error(request, subsystem,
					"Invalid password%s in passdb: %s",
					password_str, error);
	} else if (ret == 0) {
		if (log_password_mismatch)
			auth_request_log_password_mismatch(request, subsystem);
	}
	if (ret <= 0 && request->set->debug_passwords) T_BEGIN {
		log_password_failure(request, plain_password,
				     crypted_password, scheme,
				     &gen_params,
				     subsystem);
	} T_END;
	return ret;
}

static void get_log_prefix(string_t *str, struct auth_request *auth_request,
			   const char *subsystem)
{
#define MAX_LOG_USERNAME_LEN 64
	const char *ip, *name;

	if (subsystem == AUTH_SUBSYS_DB) {
		if (!auth_request->userdb_lookup) {
			i_assert(auth_request->passdb != NULL);
			name = auth_request->passdb->set->name[0] != '\0' ?
				auth_request->passdb->set->name :
				auth_request->passdb->passdb->iface.name;
		} else {
			i_assert(auth_request->userdb != NULL);
			name = auth_request->userdb->set->name[0] != '\0' ?
				auth_request->userdb->set->name :
				auth_request->userdb->userdb->iface->name;
		}
	} else if (subsystem == AUTH_SUBSYS_MECH) {
		i_assert(auth_request->mech != NULL);
		name = t_str_lcase(auth_request->mech->mech_name);
	} else {
		name = subsystem;
	}
	str_append(str, name);
	str_append_c(str, '(');

	if (auth_request->user == NULL)
		str_append(str, "?");
	else {
		str_sanitize_append(str, auth_request->user,
				    MAX_LOG_USERNAME_LEN);
	}

	ip = net_ip2addr(&auth_request->remote_ip);
	if (ip[0] != '\0') {
		str_append_c(str, ',');
		str_append(str, ip);
	}
	if (auth_request->requested_login_user != NULL)
		str_append(str, ",master");
	if (auth_request->session_id != NULL)
		str_printfa(str, ",<%s>", auth_request->session_id);
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

	va_start(va, format);
	T_BEGIN {
		e_debug(auth_request->event, "%s", get_log_str(auth_request, subsystem, format, va));
	} T_END;
	va_end(va);
}

void auth_request_log_info(struct auth_request *auth_request,
			   const char *subsystem,
			   const char *format, ...)
{
	va_list va;

	if (auth_request->set->debug) {
		/* auth_debug=yes overrides auth_verbose settings */
	} else {
		const char *db_auth_verbose;

		if (auth_request->userdb_lookup)
			db_auth_verbose = auth_request->userdb->set->auth_verbose;
		else if (auth_request->passdb != NULL)
			db_auth_verbose = auth_request->passdb->set->auth_verbose;
		else
			db_auth_verbose = "d";
		switch (db_auth_verbose[0]) {
		case 'y':
			break;
		case 'n':
			return;
		case 'd':
			if (!auth_request->set->verbose)
				return;
			break;
		default:
			i_unreached();
		}
	}

	va_start(va, format);
	T_BEGIN {
		i_info("%s", get_log_str(auth_request, subsystem, format, va));
	} T_END;
	va_end(va);
}

void auth_request_log_warning(struct auth_request *auth_request,
			      const char *subsystem,
			      const char *format, ...)
{
	va_list va;

	va_start(va, format);
	T_BEGIN {
		i_warning("%s", get_log_str(auth_request, subsystem, format, va));
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
