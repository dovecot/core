/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "auth.h"
#include "cookie.h"

#include <stdlib.h>

struct auth_module_list {
	struct auth_module_list *next;

	struct auth_module module;
};

enum auth_mech auth_mechanisms;
const char *const *auth_realms;

static int set_use_cyrus_sasl;
static struct auth_module_list *auth_modules;
static struct auth_reply_data failure_reply;

void auth_register_module(struct auth_module *module)
{
	struct auth_module_list *list;

	i_assert((auth_mechanisms & module->mech) == 0);

	auth_mechanisms |= module->mech;

	list = i_new(struct auth_module_list, 1);
	memcpy(&list->module, module, sizeof(struct auth_module));

	list->next = auth_modules;
	auth_modules = list;
}

void auth_unregister_module(struct auth_module *module)
{
	struct auth_module_list **pos, *list;

	if ((auth_mechanisms & module->mech) == 0)
		return; /* not registered */

        auth_mechanisms &= ~module->mech;

	for (pos = &auth_modules; *pos != NULL; pos = &(*pos)->next) {
		if ((*pos)->module.mech == module->mech) {
			list = *pos;
			*pos = (*pos)->next;
			i_free(list);
			break;
		}
	}
}

void auth_init_request(unsigned int login_pid,
		       struct auth_init_request_data *request,
		       AuthCallback callback, void *context)
{
	struct auth_module_list *list;

	if ((auth_mechanisms & request->mech) == 0) {
		/* unsupported mechanism */
		i_error("BUG: imap-login requested unsupported "
			"auth mechanism %d", request->mech);
		failure_reply.id = request->id;
		callback(&failure_reply, NULL, context);
		return;
	}

#ifdef USE_CYRUS_SASL2
	if (set_use_cyrus_sasl) {
		auth_cyrus_sasl_init(login_pid, request, callback, context);
		return;
	}
#endif

	for (list = auth_modules; list != NULL; list = list->next) {
		if (list->module.mech == request->mech) {
			list->module.init(login_pid, request,
					  callback, context);
			return;
		}
	}
	i_unreached();
}

void auth_continue_request(unsigned int login_pid,
			   struct auth_continued_request_data *request,
			   const unsigned char *data,
			   AuthCallback callback, void *context)
{
	struct cookie_data *cookie_data;

	cookie_data = cookie_lookup(request->cookie);
	if (cookie_data == NULL) {
		/* timeouted cookie */
		failure_reply.id = request->id;
		callback(&failure_reply, NULL, context);
	} else if (cookie_data->login_pid != login_pid) {
		i_error("BUG: imap-login requested cookie it didn't own");
	} else {
		cookie_data->auth_continue(cookie_data, request,
					   data, callback, context);
	}
}

extern struct auth_module auth_plain;
extern struct auth_module auth_digest_md5;

void auth_init(void)
{
	const char *const *mechanisms;
	const char *env;

        auth_modules = NULL;
	auth_mechanisms = 0;

	memset(&failure_reply, 0, sizeof(failure_reply));
	failure_reply.result = AUTH_RESULT_FAILURE;

	/* register wanted mechanisms */
	env = getenv("MECHANISMS");
	if (env == NULL || *env == '\0')
		i_fatal("MECHANISMS environment is unset");

	mechanisms = t_strsplit(env, " ");
	while (*mechanisms != NULL) {
		if (strcasecmp(*mechanisms, "PLAIN") == 0)
			auth_register_module(&auth_plain);
		else if (strcasecmp(*mechanisms, "DIGEST-MD5") == 0)
			auth_register_module(&auth_digest_md5);
		else {
			i_fatal("Unknown authentication mechanism '%s'",
				*mechanisms);
		}

		mechanisms++;
	}

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
		auth_cyrus_sasl_init_lib();
#endif
}

void auth_deinit(void)
{
	auth_unregister_module(&auth_plain);
	auth_unregister_module(&auth_digest_md5);
}
