/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "ioloop.h"
#include "str.h"
#include "strfuncs.h"
#include "passdb.h"

#include "sasl-server-private.h"

#include <ctype.h>

static struct mech_module_list *mech_modules;

void mech_register_module(const struct sasl_server_mech_def *module)
{
	struct mech_module_list *list;
	i_assert(strcmp(module->name, t_str_ucase(module->name)) == 0);

	list = i_new(struct mech_module_list, 1);
	list->module = module;

	list->next = mech_modules;
	mech_modules = list;
}

void mech_unregister_module(const struct sasl_server_mech_def *module)
{
	struct mech_module_list **pos, *list;

	for (pos = &mech_modules; *pos != NULL; pos = &(*pos)->next) {
		if (strcmp((*pos)->module->name, module->name) == 0) {
			list = *pos;
			*pos = (*pos)->next;
			i_free(list);
			break;
		}
	}
}

const struct sasl_server_mech_def *mech_module_find(const char *name)
{
	struct mech_module_list *list;
	name = t_str_ucase(name);

	for (list = mech_modules; list != NULL; list = list->next) {
		if (strcmp(list->module->name, name) == 0)
			return list->module;
	}
	return NULL;
}

extern const struct sasl_server_mech_def mech_plain;
extern const struct sasl_server_mech_def mech_login;
extern const struct sasl_server_mech_def mech_apop;
extern const struct sasl_server_mech_def mech_cram_md5;
extern const struct sasl_server_mech_def mech_digest_md5;
extern const struct sasl_server_mech_def mech_external;
extern const struct sasl_server_mech_def mech_otp;
extern const struct sasl_server_mech_def mech_scram_sha1;
extern const struct sasl_server_mech_def mech_scram_sha1_plus;
extern const struct sasl_server_mech_def mech_scram_sha256;
extern const struct sasl_server_mech_def mech_scram_sha256_plus;
extern const struct sasl_server_mech_def mech_anonymous;
#ifdef HAVE_GSSAPI
extern const struct sasl_server_mech_def mech_gssapi;
#endif
#ifdef HAVE_GSSAPI_SPNEGO
extern const struct sasl_server_mech_def mech_gssapi_spnego;
#endif
extern const struct sasl_server_mech_def mech_winbind_ntlm;
extern const struct sasl_server_mech_def mech_winbind_spnego;
extern const struct sasl_server_mech_def mech_oauthbearer;
extern const struct sasl_server_mech_def mech_xoauth2;

void mech_register_add(struct mechanisms_register *reg,
		       const struct sasl_server_mech_def *mech);

const char *mech_get_plugin_name(const char *name);

struct mechanisms_register *
mech_register_init(const struct auth_settings *set);

void mech_register_deinit(struct mechanisms_register **_reg)
{
	struct mechanisms_register *reg = *_reg;

	*_reg = NULL;
	pool_unref(&reg->pool);
}

const struct sasl_server_mech_def *
mech_register_find(const struct mechanisms_register *reg, const char *name)
{
	const struct mech_module_list *list;
	name = t_str_ucase(name);

	for (list = reg->modules; list != NULL; list = list->next) {
		if (strcmp(list->module->name, name) == 0)
			return list->module;
	}
	return NULL;
}

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
#if defined(HAVE_GSSAPI_SPNEGO) && defined(BUILTIN_GSSAPI)
		mech_register_module(&mech_gssapi_spnego);
#endif
	}
	mech_register_module(&mech_otp);
	mech_register_module(&mech_scram_sha1);
	mech_register_module(&mech_scram_sha1_plus);
	mech_register_module(&mech_scram_sha256);
	mech_register_module(&mech_scram_sha256_plus);
	mech_register_module(&mech_anonymous);
#ifdef BUILTIN_GSSAPI
	mech_register_module(&mech_gssapi);
#endif
	mech_register_module(&mech_oauthbearer);
	mech_register_module(&mech_xoauth2);
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
#if defined(HAVE_GSSAPI_SPNEGO) && defined(BUILTIN_GSSAPI)
		mech_unregister_module(&mech_gssapi_spnego);
#endif
	}
	mech_unregister_module(&mech_otp);
	mech_unregister_module(&mech_scram_sha1);
	mech_unregister_module(&mech_scram_sha1_plus);
	mech_unregister_module(&mech_scram_sha256);
	mech_unregister_module(&mech_scram_sha256_plus);
	mech_unregister_module(&mech_anonymous);
#ifdef BUILTIN_GSSAPI
	mech_unregister_module(&mech_gssapi);
#endif
	mech_unregister_module(&mech_oauthbearer);
	mech_unregister_module(&mech_xoauth2);
}
