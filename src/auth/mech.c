/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "buffer.h"
#include "hash.h"
#include "mech.h"
#include "login-connection.h"

#include <stdlib.h>

struct mech_module_list {
	struct mech_module_list *next;

	struct mech_module module;
};

enum auth_mech auth_mechanisms;
const char *const *auth_realms;

static int set_use_cyrus_sasl;
static struct mech_module_list *mech_modules;
static struct auth_login_reply failure_reply;

void mech_register_module(struct mech_module *module)
{
	struct mech_module_list *list;

	i_assert((auth_mechanisms & module->mech) == 0);

	auth_mechanisms |= module->mech;

	list = i_new(struct mech_module_list, 1);
	list->module = *module;

	list->next = mech_modules;
	mech_modules = list;
}

void mech_unregister_module(struct mech_module *module)
{
	struct mech_module_list **pos, *list;

	if ((auth_mechanisms & module->mech) == 0)
		return; /* not registered */

        auth_mechanisms &= ~module->mech;

	for (pos = &mech_modules; *pos != NULL; pos = &(*pos)->next) {
		if ((*pos)->module.mech == module->mech) {
			list = *pos;
			*pos = (*pos)->next;
			i_free(list);
			break;
		}
	}
}

void mech_request_new(struct login_connection *conn,
		      struct auth_login_request_new *request,
		      mech_callback_t *callback)
{
	struct mech_module_list *list;
	struct auth_request *auth_request;

	if ((auth_mechanisms & request->mech) == 0) {
		/* unsupported mechanism */
		i_error("BUG: login requested unsupported "
			"auth mechanism %d", request->mech);
		failure_reply.id = request->id;
		callback(&failure_reply, NULL, conn);
		return;
	}

#ifdef USE_CYRUS_SASL2
	if (set_use_cyrus_sasl) {
		auth_request = mech_cyrus_sasl_new(conn, request, callback);
	} else
#endif
	{
		auth_request = NULL;

		for (list = mech_modules; list != NULL; list = list->next) {
			if (list->module.mech == request->mech) {
				auth_request =
					list->module.auth_new(conn, request->id,
							      callback);
				break;
			}
		}
	}

	if (auth_request != NULL) {
		auth_request->protocol = request->protocol;
		hash_insert(conn->auth_requests, POINTER_CAST(request->id),
			    auth_request);
	}
}

void mech_request_continue(struct login_connection *conn,
			   struct auth_login_request_continue *request,
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
		if (!auth_request->auth_continue(conn, auth_request,
						 request, data, callback))
                        mech_request_free(conn, auth_request, request->id);
	}
}

void mech_request_free(struct login_connection *conn,
		       struct auth_request *auth_request, unsigned int id)
{
	auth_request->auth_free(auth_request);
	hash_remove(conn->auth_requests, POINTER_CAST(id));
}

void mech_init_login_reply(struct auth_login_reply *reply)
{
	memset(reply, 0, sizeof(*reply));

	reply->username_idx = (unsigned int)-1;
	reply->realm_idx = (unsigned int)-1;
	reply->reply_idx = (unsigned int)-1;
}

void *mech_auth_success(struct auth_login_reply *reply,
			struct auth_request *auth_request,
			const void *data, size_t data_size)
{
	buffer_t *buf;

	buf = buffer_create_dynamic(data_stack_pool, 256, (size_t)-1);

	reply->username_idx = 0;
	buffer_append(buf, auth_request->user, strlen(auth_request->user)+1);

	if (auth_request->realm == NULL)
		reply->realm_idx = (size_t)-1;
	else {
		reply->realm_idx = buffer_get_used_size(buf);
		buffer_append(buf, auth_request->realm,
			      strlen(auth_request->realm)+1);
	}

	if (data_size == 0)
		reply->reply_idx = (size_t)-1;
	else {
		reply->reply_idx = buffer_get_used_size(buf);
		buffer_append(buf, data, data_size);
	}

	reply->result = AUTH_LOGIN_RESULT_SUCCESS;
	reply->data_size = buffer_get_used_size(buf);
	return buffer_get_modifyable_data(buf, NULL);
}

void mech_auth_finish(struct auth_request *auth_request, int success)
{
	struct auth_login_reply reply;
	void *reply_data;

	memset(&reply, 0, sizeof(reply));
	reply.id = auth_request->id;

	if (success) {
		reply_data = mech_auth_success(&reply, auth_request, NULL, 0);
		reply.result = AUTH_LOGIN_RESULT_SUCCESS;
	} else {
		reply_data = NULL;
		reply.result = AUTH_LOGIN_RESULT_FAILURE;
	}

	auth_request->callback(&reply, reply_data, auth_request->conn);

	if (!success) {
		mech_request_free(auth_request->conn, auth_request,
				  auth_request->id);
	}
}

extern struct mech_module mech_plain;
extern struct mech_module mech_digest_md5;

void mech_init(void)
{
	const char *const *mechanisms;
	const char *env;

        mech_modules = NULL;
	auth_mechanisms = 0;

	memset(&failure_reply, 0, sizeof(failure_reply));
	failure_reply.result = AUTH_LOGIN_RESULT_FAILURE;

	/* register wanted mechanisms */
	env = getenv("MECHANISMS");
	if (env == NULL || *env == '\0')
		i_fatal("MECHANISMS environment is unset");

	mechanisms = t_strsplit(env, " ");
	while (*mechanisms != NULL) {
		if (strcasecmp(*mechanisms, "PLAIN") == 0)
			mech_register_module(&mech_plain);
		else if (strcasecmp(*mechanisms, "DIGEST-MD5") == 0)
			mech_register_module(&mech_digest_md5);
		else {
			i_fatal("Unknown authentication mechanism '%s'",
				*mechanisms);
		}

		mechanisms++;
	}

	if (auth_mechanisms == 0)
		i_fatal("No authentication mechanisms configured");

	/* get our realm - note that we allocate from data stack so
	   this function should never be called inside I/O loop or anywhere
	   else where t_pop() is called */
	env = getenv("REALMS");
	if (env == NULL)
		env = "";
	auth_realms = t_strsplit(env, " ");

	set_use_cyrus_sasl = getenv("USE_CYRUS_SASL") != NULL;

#ifdef USE_CYRUS_SASL2
	if (set_use_cyrus_sasl)
		mech_cyrus_sasl_init_lib();
#endif
}

void mech_deinit(void)
{
	mech_unregister_module(&mech_plain);
	mech_unregister_module(&mech_digest_md5);
}
