/* Copyright (C) 2005 Timo Sirainen */

#include "common.h"
#include "network.h"
#include "buffer.h"
#include "str.h"
#include "mech.h"
#include "userdb.h"
#include "passdb.h"
#include "auth.h"
#include "auth-request-handler.h"
#include "auth-request-balancer.h"

#include <stdlib.h>
#include <unistd.h>

struct auth *auth_preinit(void)
{
        struct auth *auth;
	const char *env;

	auth = i_new(struct auth, 1);

	auth->verbose = getenv("VERBOSE") != NULL;
	auth->verbose_debug = getenv("VERBOSE_DEBUG") != NULL;

	env = getenv("PASSDB");
	if (env == NULL)
		i_fatal("PASSDB environment is unset");
	passdb_preinit(auth, env);

	env = getenv("USERDB");
	if (env == NULL)
		i_fatal("USERDB environment is unset");
	userdb_preinit(auth, env);
	return auth;
}

const string_t *auth_mechanisms_get_list(struct auth *auth)
{
	struct mech_module_list *list;
	string_t *str;

	str = t_str_new(128);
	for (list = auth->mech_modules; list != NULL; list = list->next)
		str_append(str, list->module.mech_name);

	return str;
}

static void auth_mech_register(struct auth *auth, struct mech_module *mech)
{
	struct mech_module_list *list;

	list = i_new(struct mech_module_list, 1);
	list->module = *mech;

	str_printfa(auth->mech_handshake, "MECH\t%s", mech->mech_name);
	if ((mech->flags & MECH_SEC_PRIVATE) != 0)
		str_append(auth->mech_handshake, "\tprivate");
	if ((mech->flags & MECH_SEC_ANONYMOUS) != 0)
		str_append(auth->mech_handshake, "\tanonymous");
	if ((mech->flags & MECH_SEC_PLAINTEXT) != 0)
		str_append(auth->mech_handshake, "\tplaintext");
	if ((mech->flags & MECH_SEC_DICTIONARY) != 0)
		str_append(auth->mech_handshake, "\tdictionary");
	if ((mech->flags & MECH_SEC_ACTIVE) != 0)
		str_append(auth->mech_handshake, "\tactive");
	if ((mech->flags & MECH_SEC_FORWARD_SECRECY) != 0)
		str_append(auth->mech_handshake, "\tforward-secrecy");
	if ((mech->flags & MECH_SEC_MUTUAL_AUTH) != 0)
		str_append(auth->mech_handshake, "\tmutual-auth");
	str_append_c(auth->mech_handshake, '\n');

	list->next = auth->mech_modules;
	auth->mech_modules = list;
}

static void auth_mech_list_verify_passdb(struct auth *auth)
{
	struct mech_module_list *list;

	for (list = auth->mech_modules; list != NULL; list = list->next) {
		if (list->module.passdb_need_plain &&
		    auth->passdb->verify_plain == NULL)
			break;
		if (list->module.passdb_need_credentials &&
		    auth->passdb->lookup_credentials == NULL)
			break;
	}

	if (list != NULL) {
		i_fatal("Passdb %s doesn't support %s method",
			auth->passdb->name, list->module.mech_name);
	}
}

void auth_init(struct auth *auth)
{
	struct mech_module *mech;
	const char *const *mechanisms;
	const char *env;

	passdb_init(auth);
	userdb_init(auth);

	auth->mech_handshake = str_new(default_pool, 512);

	auth->anonymous_username = getenv("ANONYMOUS_USERNAME");
	if (auth->anonymous_username != NULL &&
	    *auth->anonymous_username == '\0')
                auth->anonymous_username = NULL;

	/* register wanted mechanisms */
	env = getenv("MECHANISMS");
	if (env == NULL)
		i_fatal("MECHANISMS environment is unset");

	mechanisms = t_strsplit_spaces(env, " ");
	while (*mechanisms != NULL) {
		if (strcasecmp(*mechanisms, "ANONYMOUS") == 0) {
			if (auth->anonymous_username == NULL) {
				i_fatal("ANONYMOUS listed in mechanisms, "
					"but anonymous_username not given");
			}
		}
		mech = mech_module_find(*mechanisms);
		if (mech == NULL) {
			i_fatal("Unknown authentication mechanism '%s'",
				*mechanisms);
		}
		auth_mech_register(auth, mech);

		mechanisms++;
	}

	if (auth->mech_modules == NULL)
		i_fatal("No authentication mechanisms configured");
	auth_mech_list_verify_passdb(auth);

	/* get our realm - note that we allocate from data stack so
	   this function should never be called inside I/O loop or anywhere
	   else where t_pop() is called */
	env = getenv("REALMS");
	if (env == NULL)
		env = "";
	auth->auth_realms = t_strsplit_spaces(env, " ");

	auth->default_realm = getenv("DEFAULT_REALM");
	if (auth->default_realm != NULL && *auth->default_realm == '\0')
		auth->default_realm = NULL;

	env = getenv("USERNAME_CHARS");
	if (env == NULL || *env == '\0') {
		/* all chars are allowed */
		memset(auth->username_chars, 1, sizeof(auth->username_chars));
	} else {
		for (; *env != '\0'; env++)
			auth->username_chars[(int)(uint8_t)*env] = 1;
	}

	env = getenv("USERNAME_TRANSLATION");
	if (env != NULL) {
		for (; *env != '\0' && env[1] != '\0'; env += 2)
			auth->username_translation[(int)(uint8_t)*env] = env[1];
	}

	auth->ssl_require_client_cert =
		getenv("SSL_REQUIRE_CLIENT_CERT") != NULL;
}

void auth_deinit(struct auth *auth)
{
	userdb_deinit(auth);
	passdb_deinit(auth);

	if (auth->balancer_worker != NULL)
		auth_request_balancer_worker_destroy(auth->balancer_worker);

	str_free(auth->mech_handshake);
}
