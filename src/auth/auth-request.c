/* Copyright (C) 2002-2005 Timo Sirainen */

#include "common.h"
#include "ioloop.h"
#include "buffer.h"
#include "hash.h"
#include "str.h"
#include "safe-memset.h"
#include "str-sanitize.h"
#include "var-expand.h"
#include "auth-request.h"
#include "auth-client-connection.h"
#include "auth-master-connection.h"
#include "passdb.h"
#include "passdb-cache.h"

struct auth_request *
auth_request_new(struct auth *auth, struct mech_module *mech,
		 mech_callback_t *callback, void *context)
{
	struct auth_request *request;

	request = mech->auth_new();

	request->refcount = 1;
	request->created = ioloop_time;

	request->auth = auth;
	request->mech = mech;
	request->callback = callback;
	request->context = context;
	return request;
}

void auth_request_success(struct auth_request *request,
			  const void *data, size_t data_size)
{
	i_assert(!request->finished);
	request->finished = TRUE;

	request->successful = TRUE;
	request->callback(request, AUTH_CLIENT_RESULT_SUCCESS,
			  data, data_size);
}

void auth_request_fail(struct auth_request *request)
{
	i_assert(!request->finished);
	request->finished = TRUE;

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

int auth_request_unref(struct auth_request *request)
{
	i_assert(request->refcount > 0);
	if (--request->refcount > 0)
		return TRUE;

	request->mech->auth_free(request);
	return FALSE;
}

void auth_request_initial(struct auth_request *request,
			  const unsigned char *data, size_t data_size)
{
	request->mech->auth_initial(request, data, data_size);
}

void auth_request_continue(struct auth_request *request,
			   const unsigned char *data, size_t data_size)
{
	request->mech->auth_continue(request, data, data_size);
}

static void auth_request_save_cache(struct auth_request *request,
				    enum passdb_result result)
{
	struct passdb_module *passdb = request->auth->passdb;
	string_t *str;

	if (passdb_cache == NULL)
		return;

	if (passdb->cache_key == NULL)
		return;

	if (result < 0) {
		/* lookup failed. */
		if (result == PASSDB_RESULT_USER_UNKNOWN) {
			auth_cache_insert(passdb_cache, request,
					  passdb->cache_key, "");
		}
		return;
	}

	/* save all except the currently given password in cache */
	str = t_str_new(32 + str_len(request->extra_fields));
	if (request->passdb_password != NULL) {
		if (*request->passdb_password != '{') {
			/* cached passwords must have a known scheme */
			str_append_c(str, '{');
			str_append(str, passdb->default_pass_scheme);
			str_append_c(str, '}');
		}
		str_append(str, request->passdb_password);
	}
	if (request->extra_fields != NULL) {
		str_append_c(str, '\t');
		str_append_str(str, request->extra_fields);
	}
	if (request->no_failure_delay) {
		str_append_c(str, '\t');
		str_append(str, "nodelay");
	}
	auth_cache_insert(passdb_cache, request, passdb->cache_key, str_c(str));
}

static void auth_request_verify_plain_callback(enum passdb_result result,
					       struct auth_request *request)
{
        auth_request_save_cache(request, result);

	if (request->proxy) {
		/* we're proxying - send back the password that was
		   sent by user (not the password in passdb). */
		str_printfa(request->extra_fields, "\tpass=%s",
			    request->mech_password);
	}

	if (request->passdb_password != NULL) {
		safe_memset(request->passdb_password, 0,
			    strlen(request->mech_password));
	}

        safe_memset(request->mech_password, 0, strlen(request->mech_password));
	request->private_callback.verify_plain(result, request);
}

void auth_request_verify_plain(struct auth_request *request,
			       const char *password,
			       verify_plain_callback_t *callback)
{
	struct passdb_module *passdb = request->auth->passdb;
	enum passdb_result result;
	const char *cache_key;

	cache_key = passdb_cache == NULL ? NULL : passdb->cache_key;
	if (cache_key != NULL) {
		if (passdb_cache_verify_plain(request, cache_key, password,
					      &result)) {
			callback(result, request);
			return;
		}
	}

	request->mech_password = p_strdup(request->pool, password);
	request->private_callback.verify_plain = callback;
	passdb->verify_plain(request, password,
			     auth_request_verify_plain_callback);
}

static void
auth_request_lookup_credentials_callback(enum passdb_result result,
					 const char *credentials,
					 struct auth_request *request)
{
        auth_request_save_cache(request, result);

	if (request->passdb_password != NULL) {
		safe_memset(request->passdb_password, 0,
			    strlen(request->mech_password));
	}

	request->private_callback.lookup_credentials(result, credentials,
						     request);
}

void auth_request_lookup_credentials(struct auth_request *request,
				     enum passdb_credentials credentials,
				     lookup_credentials_callback_t *callback)
{
	struct passdb_module *passdb = request->auth->passdb;
	const char *cache_key, *result, *scheme;

	cache_key = passdb_cache == NULL ? NULL : passdb->cache_key;
	if (cache_key != NULL) {
		if (passdb_cache_lookup_credentials(request, cache_key,
						    &result, &scheme)) {
			passdb_handle_credentials(result != NULL ?
						  PASSDB_RESULT_OK :
						  PASSDB_RESULT_USER_UNKNOWN,
						  credentials, result, scheme,
						  callback, request);
			return;
		}
	}

	request->private_callback.lookup_credentials = callback;
	passdb->lookup_credentials(request, credentials,
				   auth_request_lookup_credentials_callback);
}

void auth_request_lookup_user(struct auth_request *request,
			      userdb_callback_t *callback, void *context)
{
	request->auth->userdb->lookup(request, callback, context);
}

int auth_request_set_username(struct auth_request *request,
			      const char *username, const char **error_r)
{
	unsigned char *p;

	if (*username == '\0') {
		/* Some PAM plugins go nuts with empty usernames */
		*error_r = "Empty username";
		return FALSE;
	}

	if (strchr(username, '@') == NULL &&
	    request->auth->default_realm != NULL) {
		request->user = p_strconcat(request->pool, username, "@",
					    request->auth->default_realm, NULL);
	} else {
		request->user = p_strdup(request->pool, username);
	}

	for (p = (unsigned char *)request->user; *p != '\0'; p++) {
		if (request->auth->username_translation[*p & 0xff] != 0)
			*p = request->auth->username_translation[*p & 0xff];
		if (request->auth->username_chars[*p & 0xff] == 0) {
			*error_r = "Username contains disallowed characters";
			return FALSE;
		}
	}

	return TRUE;
}

void auth_request_set_field(struct auth_request *request,
			    const char *name, const char *value)
{
	string_t *str;

	i_assert(value != NULL);

	if (strcmp(name, "password") == 0) {
		if (request->passdb_password == NULL) {
			request->passdb_password =
				p_strdup(request->pool, value);
		} else {
			auth_request_log_error(request, "auth",
				"Multiple password values not supported");
		}
		return;
	}

	if (strcmp(name, "nodelay") == 0) {
		/* don't delay replying to client of the failure */
		request->no_failure_delay = TRUE;
		return;
	}

	str = request->extra_fields;
	if (str == NULL)
		request->extra_fields = str = str_new(request->pool, 64);

	if (strcmp(name, "nologin") == 0) {
		/* user can't actually login - don't keep this
		   reply for master */
		request->no_login = TRUE;
		if (str_len(str) > 0)
			str_append_c(str, '\t');
		str_append(str, name);
	} else if (strcmp(name, "proxy") == 0) {
		/* we're proxying authentication for this user. send
		   password back if using plaintext authentication. */
		request->proxy = TRUE;
		if (str_len(str) > 0)
			str_append_c(str, '\t');
		str_append(str, name);
	} else {
		if (str_len(str) > 0)
			str_append_c(str, '\t');
		str_printfa(str, "%s=%s", name, value);
	}
}

static const char *escape_none(const char *str)
{
	return str;
}

const struct var_expand_table *
auth_request_get_var_expand_table(const struct auth_request *auth_request,
				  const char *(*escape_func)(const char *))
{
	static struct var_expand_table static_tab[] = {
		{ 'u', NULL },
		{ 'n', NULL },
		{ 'd', NULL },
		{ 's', NULL },
		{ 'h', NULL },
		{ 'l', NULL },
		{ 'r', NULL },
		{ 'p', NULL },
		{ '\0', NULL }
	};
	struct var_expand_table *tab;

	if (escape_func == NULL)
		escape_func = escape_none;

	tab = t_malloc(sizeof(static_tab));
	memcpy(tab, static_tab, sizeof(static_tab));

	tab[0].value = escape_func(auth_request->user);
	tab[1].value = escape_func(t_strcut(auth_request->user, '@'));
	tab[2].value = strchr(auth_request->user, '@');
	if (tab[2].value != NULL)
		tab[2].value = escape_func(tab[2].value+1);
	tab[3].value = auth_request->service;
	/* tab[4] = we have no home dir */
	if (auth_request->local_ip.family != 0)
		tab[5].value = net_ip2addr(&auth_request->local_ip);
	if (auth_request->remote_ip.family != 0)
		tab[6].value = net_ip2addr(&auth_request->remote_ip);
	tab[7].value = dec2str(auth_request->client_pid);
	return tab;
}

static const char *
get_log_str(struct auth_request *auth_request, const char *subsystem,
	    const char *format, va_list va)
{
#define MAX_LOG_USERNAME_LEN 64
	const char *ip;
	string_t *str;

	str = t_str_new(128);
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
	str_append(str, "): ");
	str_vprintfa(str, format, va);
	return str_c(str);
}

void auth_request_log_debug(struct auth_request *auth_request,
			    const char *subsystem,
			    const char *format, ...)
{
	va_list va;

	if (!auth_request->auth->verbose_debug)
		return;

	va_start(va, format);
	t_push();
	i_info("%s", get_log_str(auth_request, subsystem, format, va));
	t_pop();
	va_end(va);
}

void auth_request_log_info(struct auth_request *auth_request,
			   const char *subsystem,
			   const char *format, ...)
{
	va_list va;

	if (!auth_request->auth->verbose)
		return;

	va_start(va, format);
	t_push();
	i_info("%s", get_log_str(auth_request, subsystem, format, va));
	t_pop();
	va_end(va);
}

void auth_request_log_error(struct auth_request *auth_request,
			    const char *subsystem,
			    const char *format, ...)
{
	va_list va;

	va_start(va, format);
	t_push();
	i_error("%s", get_log_str(auth_request, subsystem, format, va));
	t_pop();
	va_end(va);
}
