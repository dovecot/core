/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "ioloop.h"
#include "buffer.h"
#include "hash.h"
#include "mech.h"
#include "str.h"
#include "var-expand.h"
#include "auth-client-connection.h"
#include "auth-master-connection.h"

#include <stdlib.h>

struct mech_module_list *mech_modules;
const char *const *auth_realms;
const char *default_realm;
const char *anonymous_username;
char username_chars[256];

static int set_use_cyrus_sasl;
static int ssl_require_client_cert;
static struct auth_client_request_reply failure_reply;

void mech_register_module(struct mech_module *module)
{
	struct mech_module_list *list;

	list = i_new(struct mech_module_list, 1);
	list->module = *module;

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

static struct mech_module *mech_module_find(const char *name)
{
	struct mech_module_list *list;

	for (list = mech_modules; list != NULL; list = list->next) {
		if (strcasecmp(list->module.mech_name, name) == 0)
			return &list->module;
	}
	return NULL;
}

void mech_request_new(struct auth_client_connection *conn,
		      struct auth_client_request_new *request,
		      const unsigned char *data,
		      mech_callback_t *callback)
{
        struct mech_module *mech;
	struct auth_request *auth_request;

	/* make sure data is NUL-terminated */
	if (request->data_size == 0 || request->initial_resp_idx == 0 ||
	    request->mech_idx >= request->data_size ||
	    request->protocol_idx >= request->data_size ||
	    request->initial_resp_idx > request->data_size ||
	    data[request->initial_resp_idx-1] != '\0') {
		i_error("BUG: Auth client %u sent corrupted request",
			conn->pid);
		failure_reply.id = request->id;
		callback(&failure_reply, NULL, conn);
		return;
	}

	mech = mech_module_find((const char *)data + request->mech_idx);
	if (mech == NULL) {
		/* unsupported mechanism */
		i_error("BUG: Auth client %u requested unsupported "
			"auth mechanism %s", conn->pid,
			(const char *)data + request->mech_idx);
		failure_reply.id = request->id;
		callback(&failure_reply, NULL, conn);
		return;
	}

	if (ssl_require_client_cert &&
	    (request->flags & AUTH_CLIENT_FLAG_SSL_VALID_CLIENT_CERT) == 0) {
		/* we fail without valid certificate */
		if (verbose)
			i_info("Client didn't present valid SSL certificate");
		failure_reply.id = request->id;
		callback(&failure_reply, NULL, conn);
		return;
	}

#ifdef USE_CYRUS_SASL2
	if (set_use_cyrus_sasl)
		auth_request = mech_cyrus_sasl_new(conn, request, callback);
	else
#endif
		auth_request = mech->auth_new();

	if (auth_request != NULL) {
		auth_request->created = ioloop_time;
		auth_request->conn = conn;
		auth_request->id = request->id;
		auth_request->protocol =
			p_strdup(auth_request->pool,
				 (const char *)data + request->protocol_idx);

		hash_insert(conn->auth_requests, POINTER_CAST(request->id),
			    auth_request);

		if (!auth_request->auth_initial(auth_request, request, data,
						callback))
			mech_request_free(auth_request, request->id);
	}
}

void mech_request_continue(struct auth_client_connection *conn,
			   struct auth_client_request_continue *request,
			   const unsigned char *data,
			   mech_callback_t *callback)
{
	struct auth_request *auth_request;

	auth_request = hash_lookup(conn->auth_requests,
				   POINTER_CAST(request->id));
	if (auth_request == NULL) {
		/* timeouted */
		failure_reply.id = request->id;
		callback(&failure_reply, NULL, conn);
	} else {
		if (!auth_request->auth_continue(auth_request,
						 data, request->data_size,
						 callback))
			mech_request_free(auth_request, request->id);
	}
}

void mech_request_free(struct auth_request *auth_request, unsigned int id)
{
	if (auth_request->conn != NULL) {
		hash_remove(auth_request->conn->auth_requests,
			    POINTER_CAST(id));
	}
	auth_request_unref(auth_request);
}

void mech_init_auth_client_reply(struct auth_client_request_reply *reply)
{
	memset(reply, 0, sizeof(*reply));

	reply->username_idx = (size_t)-1;
	reply->reply_idx = (size_t)-1;
}

void *mech_auth_success(struct auth_client_request_reply *reply,
			struct auth_request *auth_request,
			const void *data, size_t data_size)
{
	buffer_t *buf;

	buf = buffer_create_dynamic(pool_datastack_create(), 256, (size_t)-1);

	reply->username_idx = 0;
	buffer_append(buf, auth_request->user, strlen(auth_request->user)+1);

	if (data_size == 0)
		reply->reply_idx = (size_t)-1;
	else {
		reply->reply_idx = buffer_get_used_size(buf);
		buffer_append(buf, data, data_size);
	}

	reply->result = AUTH_CLIENT_RESULT_SUCCESS;
	reply->data_size = buffer_get_used_size(buf);
	return buffer_get_modifyable_data(buf, NULL);
}

void mech_auth_finish(struct auth_request *auth_request,
		      const void *data, size_t data_size, int success)
{
	struct auth_client_request_reply reply;
	void *reply_data;

	memset(&reply, 0, sizeof(reply));
	reply.id = auth_request->id;

	if (success) {
		reply_data = mech_auth_success(&reply, auth_request,
					       data, data_size);
		reply.result = AUTH_CLIENT_RESULT_SUCCESS;
	} else {
		reply_data = NULL;
		reply.result = AUTH_CLIENT_RESULT_FAILURE;
	}

	auth_request->callback(&reply, reply_data, auth_request->conn);

	if (!success || AUTH_MASTER_IS_DUMMY(auth_request->conn->master)) {
		/* request is no longer needed, either because the
		   authentication failed or because we don't have master
		   process */
		mech_request_free(auth_request, auth_request->id);
	}
}

int mech_is_valid_username(const char *username)
{
	const unsigned char *p;

	for (p = (const unsigned char *)username; *p != '\0'; p++) {
		if (username_chars[*p & 0xff] == 0)
			return FALSE;
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

	request->auth_free(request);
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
	tab[3].value = auth_request->protocol;
	return tab;
}

extern struct mech_module mech_plain;
extern struct mech_module mech_cram_md5;
extern struct mech_module mech_digest_md5;
extern struct mech_module mech_anonymous;

void mech_init(void)
{
	const char *const *mechanisms;
	const char *env;

        mech_modules = NULL;

	memset(&failure_reply, 0, sizeof(failure_reply));
	failure_reply.result = AUTH_CLIENT_RESULT_FAILURE;

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
		else if (strcasecmp(*mechanisms, "CRAM-MD5") == 0)
			mech_register_module(&mech_cram_md5);
		else if (strcasecmp(*mechanisms, "DIGEST-MD5") == 0)
			mech_register_module(&mech_digest_md5);
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
		memset(username_chars, 0xff, sizeof(username_chars));
	} else {
		memset(username_chars, 0, sizeof(username_chars));
		for (; *env != '\0'; env++)
			username_chars[((unsigned char)*env) & 0xff] = 0xff;
	}

	set_use_cyrus_sasl = getenv("USE_CYRUS_SASL") != NULL;
#ifdef USE_CYRUS_SASL2
	if (set_use_cyrus_sasl)
		mech_cyrus_sasl_init_lib();
#endif
        ssl_require_client_cert = getenv("SSL_REQUIRE_CLIENT_CERT") != NULL;
}

void mech_deinit(void)
{
	mech_unregister_module(&mech_plain);
	mech_unregister_module(&mech_cram_md5);
	mech_unregister_module(&mech_digest_md5);
	mech_unregister_module(&mech_anonymous);
}
