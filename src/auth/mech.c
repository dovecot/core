/* Copyright (c) 2002-2010 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "ioloop.h"
#include "mech.h"
#include "str.h"
#include "passdb.h"

#include <stdlib.h>

static struct mech_module_list *mech_modules;

void mech_register_module(const struct mech_module *module)
{
	struct mech_module_list *list;

	list = i_new(struct mech_module_list, 1);
	list->module = *module;

	list->next = mech_modules;
	mech_modules = list;
}

void mech_unregister_module(const struct mech_module *module)
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

const struct mech_module *mech_module_find(const char *name)
{
	struct mech_module_list *list;

	for (list = mech_modules; list != NULL; list = list->next) {
		if (strcasecmp(list->module.mech_name, name) == 0)
			return &list->module;
	}
	return NULL;
}

void mech_generic_auth_initial(struct auth_request *request,
			       const unsigned char *data, size_t data_size)
{
	if (data == NULL) {
		request->callback(request, AUTH_CLIENT_RESULT_CONTINUE,
				  NULL, 0);
	} else {
		/* initial reply given, even if it was 0 bytes */
		request->mech->auth_continue(request, data, data_size);
	}
}

void mech_generic_auth_free(struct auth_request *request)
{
	pool_unref(&request->pool);
}

extern const struct mech_module mech_plain;
extern const struct mech_module mech_login;
extern const struct mech_module mech_apop;
extern const struct mech_module mech_cram_md5;
extern const struct mech_module mech_digest_md5;
extern const struct mech_module mech_external;
extern const struct mech_module mech_ntlm;
extern const struct mech_module mech_otp;
extern const struct mech_module mech_skey;
extern const struct mech_module mech_rpa;
extern const struct mech_module mech_anonymous;
#ifdef HAVE_GSSAPI
extern const struct mech_module mech_gssapi;
#endif
#ifdef HAVE_GSSAPI_SPNEGO
extern const struct mech_module mech_gssapi_spnego;
#endif
extern const struct mech_module mech_winbind_ntlm;
extern const struct mech_module mech_winbind_spnego;

void mech_init(const struct auth_settings *set)
{
	mech_register_module(&mech_plain);
	mech_register_module(&mech_login);
	mech_register_module(&mech_apop);
	mech_register_module(&mech_cram_md5);
	mech_register_module(&mech_digest_md5);
	mech_register_module(&mech_external);
	if (set->use_winbind) {
		mech_register_module(&mech_winbind_ntlm);
		mech_register_module(&mech_winbind_spnego);
	} else {
		mech_register_module(&mech_ntlm);
#if defined(HAVE_GSSAPI_SPNEGO) && defined(BUILTIN_GSSAPI)
		mech_register_module(&mech_gssapi_spnego);
#endif
	}
	mech_register_module(&mech_otp);
	mech_register_module(&mech_skey);
	mech_register_module(&mech_rpa);
	mech_register_module(&mech_anonymous);
#ifdef BUILTIN_GSSAPI
	mech_register_module(&mech_gssapi);
#endif
}

void mech_deinit(const struct auth_settings *set)
{
	mech_unregister_module(&mech_plain);
	mech_unregister_module(&mech_login);
	mech_unregister_module(&mech_apop);
	mech_unregister_module(&mech_cram_md5);
	mech_unregister_module(&mech_digest_md5);
	mech_unregister_module(&mech_external);
	if (set->use_winbind) {
		mech_unregister_module(&mech_winbind_ntlm);
		mech_unregister_module(&mech_winbind_spnego);
	} else {
		mech_unregister_module(&mech_ntlm);
#if defined(HAVE_GSSAPI_SPNEGO) && defined(BUILTIN_GSSAPI)
		mech_unregister_module(&mech_gssapi_spnego);
#endif
	}
	mech_unregister_module(&mech_otp);
	mech_unregister_module(&mech_skey);
	mech_unregister_module(&mech_rpa);
	mech_unregister_module(&mech_anonymous);
#ifdef BUILTIN_GSSAPI
	mech_unregister_module(&mech_gssapi);
#endif
}
