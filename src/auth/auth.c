/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "auth.h"
#include "cookie.h"

#include <stdlib.h>

typedef struct _AuthModuleList AuthModuleList;

struct _AuthModuleList {
	AuthModuleList *next;

	AuthModule module;
};

AuthMethod auth_methods;
char *const *auth_realms;

static AuthModuleList *auth_modules;
static AuthReplyData failure_reply;

void auth_register_module(AuthModule *module)
{
	AuthModuleList *list;

	i_assert((auth_methods & module->method) == 0);

	auth_methods |= module->method;

	list = i_new(AuthModuleList, 1);
	memcpy(&list->module, module, sizeof(AuthModule));

	list->next = auth_modules;
	auth_modules = list;
}

void auth_unregister_module(AuthModule *module)
{
	AuthModuleList **pos, *list;

	if ((auth_methods & module->method) == 0)
		return; /* not registered */

        auth_methods &= ~module->method;

	for (pos = &auth_modules; *pos != NULL; pos = &(*pos)->next) {
		if ((*pos)->module.method == module->method) {
			list = *pos;
			*pos = (*pos)->next;
			i_free(list);
			break;
		}
	}
}

void auth_init_request(AuthInitRequestData *request,
		       AuthCallback callback, void *context)
{
	AuthModuleList *list;

	if ((auth_methods & request->method) == 0) {
		/* unsupported method */
		i_error("BUG: imap-login requested unsupported "
			"auth method %d", request->method);
		failure_reply.id = request->id;
		callback(&failure_reply, NULL, context);
		return;
	}

	for (list = auth_modules; list != NULL; list = list->next) {
		if (list->module.method == request->method) {
			list->module.init(request, callback, context);
			return;
		}
	}

	i_assert(0);
}

void auth_continue_request(AuthContinuedRequestData *request,
			   const unsigned char *data,
			   AuthCallback callback, void *context)
{
	CookieData *cookie_data;

	cookie_data = cookie_lookup(request->cookie);
	if (cookie_data == NULL) {
		/* timeouted cookie */
		failure_reply.id = request->id;
		callback(&failure_reply, NULL, context);
	} else {
		cookie_data->auth_continue(cookie_data, request, data,
					   callback, context);
	}
}

extern AuthModule auth_plain;
extern AuthModule auth_digest_md5;

void auth_init(void)
{
	char *const *methods;
	const char *env;

        auth_modules = NULL;
	auth_methods = 0;

	memset(&failure_reply, 0, sizeof(failure_reply));
	failure_reply.result = AUTH_RESULT_FAILURE;

	/* register wanted methods */
	env = getenv("METHODS");
	if (env == NULL || *env == '\0')
		i_fatal("METHODS environment is unset");

	methods = t_strsplit(env, " ");
	while (*methods != NULL) {
		if (strcasecmp(*methods, "plain") == 0)
			auth_register_module(&auth_plain);
		else if (strcasecmp(*methods, "digest-md5") == 0)
			auth_register_module(&auth_digest_md5);
		else {
			i_fatal("Unknown authentication method '%s'",
				*methods);
		}
		methods++;
	}

	/* get our realm - note that we allocate from temp. memory pool so
	   this function should never be called inside I/O loop or anywhere
	   else where t_pop() is called */
	env = getenv("REALMS");
	if (env == NULL)
		env = "";
	auth_realms = t_strsplit(env, " ");
}

void auth_deinit(void)
{
	auth_unregister_module(&auth_plain);
	auth_unregister_module(&auth_digest_md5);
}
