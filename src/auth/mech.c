/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "ioloop.h"
#include "mech.h"
#include "str.h"
#include "passdb.h"

#include <stdlib.h>

struct mech_module_list *mech_modules;
string_t *mech_handshake;

const char *const *auth_realms;
const char *default_realm;
const char *anonymous_username;
char username_chars[256], username_translation[256];
int ssl_require_client_cert;

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

static void mech_list_verify_passdb(struct passdb_module *passdb)
{
	struct mech_module_list *list;

	for (list = mech_modules; list != NULL; list = list->next) {
		if (list->module.passdb_need_plain &&
		    passdb->verify_plain == NULL)
			break;
		if (list->module.passdb_need_credentials &&
		    passdb->lookup_credentials == NULL)
			break;
	}

	if (list != NULL) {
		i_fatal("Passdb %s doesn't support %s method",
			passdb->name, list->module.mech_name);
	}
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
	mech_list_verify_passdb(passdb);

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
}

void mech_deinit(void)
{
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
