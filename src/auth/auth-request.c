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

struct auth_request_extra {
	struct auth_request *request;
	string_t *str;
	char *user_password, *password;
};

static buffer_t *auth_failures_buf;
static struct timeout *to_auth_failures;

void auth_request_destroy(struct auth_request *request)
{
	i_assert(request->refcount > 0);

	if (request->destroyed)
		return;
	request->destroyed = TRUE;

	if (request->conn != NULL) {
		hash_remove(request->conn->auth_requests,
			    POINTER_CAST(request->id));
	}
	auth_request_unref(request);
}

void auth_request_success(struct auth_request *request,
			  const void *data, size_t data_size)
{
	request->successful = TRUE;
	if (request->conn != NULL) {
		request->callback(request, AUTH_CLIENT_RESULT_SUCCESS,
				  data, data_size);
	}

	if (request->no_login || request->conn == NULL ||
	    AUTH_MASTER_IS_DUMMY(request->conn->master)) {
		/* we don't have master process, the request is no longer
		   needed */
		auth_request_destroy(request);
	}
}

void auth_request_fail(struct auth_request *request)
{
	if (request->no_failure_delay) {
		/* passdb specifically requested to to delay the reply. */
		request->callback(request, AUTH_CLIENT_RESULT_FAILURE, NULL, 0);
		auth_request_destroy(request);
		return;
	}

	/* failure. don't announce it immediately to avoid
	   a) timing attacks, b) flooding */
	if (auth_failures_buf->used > 0) {
		const struct auth_request *const *requests;

		requests = auth_failures_buf->data;
		requests += auth_failures_buf->used/sizeof(*requests)-1;
		i_assert(*requests != request);
	}

	buffer_append(auth_failures_buf, &request, sizeof(request));

	/* make sure the request isn't found anymore */
	auth_request_ref(request);
	auth_request_destroy(request);
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

void auth_request_verify_plain(struct auth_request *request,
			       const char *password,
			       verify_plain_callback_t *callback)
{
	request->auth->passdb->verify_plain(request, password, callback);
}

void auth_request_lookup_credentials(struct auth_request *request,
				     enum passdb_credentials credentials,
				     lookup_credentials_callback_t *callback)
{
	request->auth->passdb->lookup_credentials(request, credentials,
						  callback);
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

struct auth_request_extra *
auth_request_extra_begin(struct auth_request *request,
			 const char *user_password)
{
	struct auth_request_extra *extra;

	extra = i_new(struct auth_request_extra, 1);
	extra->request = request;
	extra->user_password = i_strdup(user_password);
	return extra;
}

void auth_request_extra_next(struct auth_request_extra *extra,
			     const char *name, const char *value)
{
	string_t *str;

	i_assert(value != NULL);

	if (strcmp(name, "password") == 0) {
		i_assert(extra->password == NULL);
		extra->password = i_strdup(value);
		return;
	}

	if (strcmp(name, "nodelay") == 0) {
		/* don't delay replying to client of the failure */
		extra->request->no_failure_delay = TRUE;
		return;
	}

	str = extra->str;
	if (str == NULL)
		extra->str = str = str_new(extra->request->pool, 64);

	if (strcmp(name, "nologin") == 0) {
		/* user can't actually login - don't keep this
		   reply for master */
		extra->request->no_login = TRUE;
		if (str_len(str) > 0)
			str_append_c(str, '\t');
		str_append(str, name);
	} else if (strcmp(name, "proxy") == 0) {
		/* we're proxying authentication for this user. send
		   password back if using plaintext authentication. */
		extra->request->proxy = TRUE;
		if (str_len(str) > 0)
			str_append_c(str, '\t');
		str_append(str, name);
	} else {
		if (str_len(str) > 0)
			str_append_c(str, '\t');
		str_printfa(str, "%s=%s", name, value);
	}
}

void auth_request_extra_finish(struct auth_request_extra *extra,
			       const char *cache_key)
{
	string_t *str;

	if (passdb_cache != NULL && cache_key != NULL) {
		str = t_str_new(64);
		if (extra->str != NULL)
			str_append_str(str, extra->str);
		if (extra->request->no_failure_delay) {
			if (str_len(str) > 0)
				str_append_c(str, '\t');
			str_append(str, "nodelay");
		}
		auth_cache_insert(passdb_cache, extra->request, cache_key,
				  t_strconcat(extra->password == NULL ? "" :
					      extra->password,
					      str_len(str) > 0 ? "\t" : "",
					      str_c(str), NULL));
	}

	if (extra->user_password != NULL) {
		if (extra->request->proxy) {
			/* we're proxying - send back the password that was
			   sent by user (not the password in passdb). */
			str_printfa(extra->str, "\tpass=%s",
				    extra->user_password);
		}
		safe_memset(extra->user_password, 0,
			    strlen(extra->user_password));
		i_free(extra->user_password);
	}

	if (extra->str != NULL)
		extra->request->extra_fields = str_c(extra->str);

	if (extra->password != NULL) {
		safe_memset(extra->password, 0, strlen(extra->password));
		i_free(extra->password);
	}
	i_free(extra);
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
	tab[7].value = dec2str(auth_request->conn->pid);
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
	i_info("%s", get_log_str(auth_request, subsystem, format, va));
	t_pop();
	va_end(va);
}

void auth_failure_buf_flush(void)
{
	struct auth_request **auth_request;
	size_t i, size;

	auth_request = buffer_get_modifyable_data(auth_failures_buf, &size);
	size /= sizeof(*auth_request);

	for (i = 0; i < size; i++) {
		if (auth_request[i]->conn != NULL) {
			auth_request[i]->callback(auth_request[i],
						  AUTH_CLIENT_RESULT_FAILURE,
						  NULL, 0);
		}
		auth_request_destroy(auth_request[i]);
	}
	buffer_set_used_size(auth_failures_buf, 0);
}

static void auth_failure_timeout(void *context __attr_unused__)
{
	auth_failure_buf_flush();
}

void auth_requests_init(void)
{
	auth_failures_buf = buffer_create_dynamic(default_pool, 1024);
        to_auth_failures = timeout_add(2000, auth_failure_timeout, NULL);
}

void auth_requests_deinit(void)
{
	buffer_free(auth_failures_buf);
	timeout_remove(to_auth_failures);
}
