/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "ioloop.h"
#include "buffer.h"
#include "hash.h"
#include "mech.h"
#include "str.h"
#include "str-sanitize.h"
#include "var-expand.h"
#include "auth-client-connection.h"
#include "auth-master-connection.h"

#include <stdlib.h>

struct mech_module_list *mech_modules;
buffer_t *mech_handshake;

const char *const *auth_realms;
const char *default_realm;
const char *anonymous_username;
char username_chars[256], username_translation[256];
int ssl_require_client_cert;

static buffer_t *auth_failures_buf;
static struct timeout *to_auth_failures;

void mech_register_module(struct mech_module *module)
{
	struct mech_module_list *list;

	list = i_new(struct mech_module_list, 1);
	list->module = *module;

	str_printfa(mech_handshake, "MECH\t%s", module->mech_name);
	if ((module->flags & MECH_SEC_PRIVATE) != 0)
		str_append(mech_handshake, "\tprivate");
	if ((module->flags & MECH_SEC_ANONYMOUS) != 0)
		str_append(mech_handshake, "\tanonymous");
	if ((module->flags & MECH_SEC_PLAINTEXT) != 0)
		str_append(mech_handshake, "\tplaintext");
	if ((module->flags & MECH_SEC_DICTIONARY) != 0)
		str_append(mech_handshake, "\tdictionary");
	if ((module->flags & MECH_SEC_ACTIVE) != 0)
		str_append(mech_handshake, "\tactive");
	if ((module->flags & MECH_SEC_FORWARD_SECRECY) != 0)
		str_append(mech_handshake, "\tforward-secrecy");
	if ((module->flags & MECH_SEC_MUTUAL_AUTH) != 0)
		str_append(mech_handshake, "\tmutual-auth");
	str_append_c(mech_handshake, '\n');

	list->next = mech_modules;
	mech_modules = list;
}

void mech_unregister_module(struct mech_module *module)
{
	struct mech_module_list **pos, *list;

	for (pos = &mech_modules; *pos != NULL; pos = &(*pos)->next) {
		if (strcmp((*pos)->module.mech_name, module->mech_name) == 0) {
			list = *pos;
			*pos = (*pos)->next;
			i_free(list);
			break;
		}
	}
}

const string_t *auth_mechanisms_get_list(void)
{
	struct mech_module_list *list;
	string_t *str;

	str = t_str_new(128);
	for (list = mech_modules; list != NULL; list = list->next)
		str_append(str, list->module.mech_name);

	return str;
}

struct mech_module *mech_module_find(const char *name)
{
	struct mech_module_list *list;

	for (list = mech_modules; list != NULL; list = list->next) {
		if (strcasecmp(list->module.mech_name, name) == 0)
			return &list->module;
	}
	return NULL;
}

struct auth_request *auth_request_new(struct mech_module *mech)
{
	struct auth_request *request;

	request = mech->auth_new();
	if (request == NULL)
		return NULL;

	request->mech = mech;
	request->created = ioloop_time;
	return request;
}

void auth_request_destroy(struct auth_request *request)
{
	if (request->conn != NULL) {
		hash_remove(request->conn->auth_requests,
			    POINTER_CAST(request->id));
	}
	auth_request_unref(request);
}

void mech_auth_finish(struct auth_request *request,
		      const void *data, size_t data_size, int success)
{
	if (!success) {
		if (request->no_failure_delay) {
			/* passdb specifically requested to to delay the
			   reply. */
			request->callback(request, AUTH_CLIENT_RESULT_FAILURE,
					  NULL, 0);
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
		return;
	}

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

int mech_fix_username(char *username, const char **error_r)
{
	unsigned char *p;

	if (*username == '\0') {
		/* Some PAM plugins go nuts with empty usernames */
		*error_r = "Empty username";
		return FALSE;
	}

	for (p = (unsigned char *)username; *p != '\0'; p++) {
		if (username_translation[*p & 0xff] != 0)
			*p = username_translation[*p & 0xff];
		if (username_chars[*p & 0xff] == 0) {
			*error_r = "Username contains disallowed characters";
			return FALSE;
		}
	}

	return TRUE;
}

void auth_request_ref(struct auth_request *request)
{
	request->refcount++;
}

int auth_request_unref(struct auth_request *request)
{
	if (--request->refcount > 0)
		return TRUE;

	request->mech->auth_free(request);
	return FALSE;
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

const char *get_log_prefix(const struct auth_request *auth_request)
{
#define MAX_LOG_USERNAME_LEN 64
	const char *ip;
	string_t *str;

	str = t_str_new(64);

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
	return str_c(str);
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

extern struct mech_module mech_plain;
extern struct mech_module mech_login;
extern struct mech_module mech_apop;
extern struct mech_module mech_cram_md5;
extern struct mech_module mech_digest_md5;
extern struct mech_module mech_ntlm;
extern struct mech_module mech_rpa;
extern struct mech_module mech_anonymous;

void mech_init(void)
{
	const char *const *mechanisms;
	const char *env;

	mech_modules = NULL;
	mech_handshake = str_new(default_pool, 512);

	anonymous_username = getenv("ANONYMOUS_USERNAME");
	if (anonymous_username != NULL && *anonymous_username == '\0')
                anonymous_username = NULL;

	/* register wanted mechanisms */
	env = getenv("MECHANISMS");
	if (env == NULL || *env == '\0')
		i_fatal("MECHANISMS environment is unset");

	mechanisms = t_strsplit_spaces(env, " ");
	while (*mechanisms != NULL) {
		if (strcasecmp(*mechanisms, "PLAIN") == 0)
			mech_register_module(&mech_plain);
		else if (strcasecmp(*mechanisms, "LOGIN") == 0)
			mech_register_module(&mech_login);
		else if (strcasecmp(*mechanisms, "APOP") == 0)
			mech_register_module(&mech_apop);
		else if (strcasecmp(*mechanisms, "CRAM-MD5") == 0)
			mech_register_module(&mech_cram_md5);
		else if (strcasecmp(*mechanisms, "DIGEST-MD5") == 0)
			mech_register_module(&mech_digest_md5);
		else if (strcasecmp(*mechanisms, "NTLM") == 0)
			mech_register_module(&mech_ntlm);
		else if (strcasecmp(*mechanisms, "RPA") == 0)
			mech_register_module(&mech_rpa);
		else if (strcasecmp(*mechanisms, "ANONYMOUS") == 0) {
			if (anonymous_username == NULL) {
				i_fatal("ANONYMOUS listed in mechanisms, "
					"but anonymous_username not given");
			}
			mech_register_module(&mech_anonymous);
		} else {
			i_fatal("Unknown authentication mechanism '%s'",
				*mechanisms);
		}

		mechanisms++;
	}

	if (mech_modules == NULL)
		i_fatal("No authentication mechanisms configured");

	/* get our realm - note that we allocate from data stack so
	   this function should never be called inside I/O loop or anywhere
	   else where t_pop() is called */
	env = getenv("REALMS");
	if (env == NULL)
		env = "";
	auth_realms = t_strsplit_spaces(env, " ");

	default_realm = getenv("DEFAULT_REALM");
	if (default_realm != NULL && *default_realm == '\0')
		default_realm = NULL;

	env = getenv("USERNAME_CHARS");
	if (env == NULL || *env == '\0') {
		/* all chars are allowed */
		memset(username_chars, 1, sizeof(username_chars));
	} else {
		memset(username_chars, 0, sizeof(username_chars));
		for (; *env != '\0'; env++)
			username_chars[((unsigned char)*env) & 0xff] = 1;
	}

	env = getenv("USERNAME_TRANSLATION");
	memset(username_translation, 0, sizeof(username_translation));
	if (env != NULL) {
		for (; *env != '\0' && env[1] != '\0'; env += 2) {
			username_translation[((unsigned char)*env) & 0xff] =
				env[1];
		}
	}

	ssl_require_client_cert = getenv("SSL_REQUIRE_CLIENT_CERT") != NULL;

	auth_failures_buf = buffer_create_dynamic(default_pool, 1024);
        to_auth_failures = timeout_add(2000, auth_failure_timeout, NULL);
}

void mech_deinit(void)
{
	timeout_remove(to_auth_failures);

	mech_unregister_module(&mech_plain);
	mech_unregister_module(&mech_login);
	mech_unregister_module(&mech_apop);
	mech_unregister_module(&mech_cram_md5);
	mech_unregister_module(&mech_digest_md5);
	mech_unregister_module(&mech_ntlm);
	mech_unregister_module(&mech_rpa);
	mech_unregister_module(&mech_anonymous);

	str_free(mech_handshake);
}
