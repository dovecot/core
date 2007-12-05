/* Copyright (c) 2005-2007 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "network.h"
#include "buffer.h"
#include "str.h"
#include "hostpid.h"
#include "mech.h"
#include "userdb.h"
#include "passdb.h"
#include "passdb-cache.h"
#include "auth.h"
#include "auth-request-handler.h"

#include <stdlib.h>
#include <unistd.h>

struct auth *auth_preinit(void)
{
	struct auth *auth;
	struct auth_passdb *auth_passdb, **passdb_p, **masterdb_p;
	const char *driver, *args;
	pool_t pool;
	unsigned int i;

	pool = pool_alloconly_create("auth", 2048);
	auth = p_new(pool, struct auth, 1);
	auth->pool = pool;

	auth->verbose_debug_passwords =
		getenv("VERBOSE_DEBUG_PASSWORDS") != NULL;
	auth->verbose_debug = getenv("VERBOSE_DEBUG") != NULL ||
		auth->verbose_debug_passwords;
	auth->verbose = getenv("VERBOSE") != NULL || auth->verbose_debug;

	t_push();
	passdb_p = &auth->passdbs;
	masterdb_p = &auth->masterdbs;
	auth_passdb = NULL;
	for (i = 1; ; i++) {
		driver = getenv(t_strdup_printf("PASSDB_%u_DRIVER", i));
		if (driver == NULL)
			break;

                args = getenv(t_strdup_printf("PASSDB_%u_ARGS", i));
		auth_passdb = passdb_preinit(auth, driver, args, i);

                auth_passdb->deny =
                        getenv(t_strdup_printf("PASSDB_%u_DENY", i)) != NULL;
		auth_passdb->pass =
                        getenv(t_strdup_printf("PASSDB_%u_PASS", i)) != NULL;

		if (getenv(t_strdup_printf("PASSDB_%u_MASTER", i)) == NULL) {
			*passdb_p = auth_passdb;
			passdb_p = &auth_passdb->next;
                } else {
			if (auth_passdb->deny)
				i_fatal("Master passdb can't have deny=yes");

			*masterdb_p = auth_passdb;
			masterdb_p = &auth_passdb->next;
		}
	}
	if (auth_passdb != NULL && auth_passdb->pass) {
		if (masterdb_p != &auth_passdb->next)
			i_fatal("Last passdb can't have pass=yes");
		else if (auth->passdbs == NULL) {
			i_fatal("Master passdb can't have pass=yes "
				"if there are no passdbs");
		}
	}
	t_pop();

	t_push();
	for (i = 1; ; i++) {
		driver = getenv(t_strdup_printf("USERDB_%u_DRIVER", i));
		if (driver == NULL)
			break;

                args = getenv(t_strdup_printf("USERDB_%u_ARGS", i));
		userdb_preinit(auth, driver, args);
	}
	t_pop();

	if (auth->userdbs == NULL) {
		/* use a dummy userdb static. */
		userdb_preinit(auth, "static", "");
	}
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

static void auth_mech_register(struct auth *auth, const struct mech_module *mech)
{
	struct mech_module_list *list;

	list = p_new(auth->pool, struct mech_module_list, 1);
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

static bool auth_passdb_list_have_plain(struct auth *auth)
{
	struct auth_passdb *passdb;

	for (passdb = auth->passdbs; passdb != NULL; passdb = passdb->next) {
		if (passdb->passdb->iface.verify_plain != NULL)
			return TRUE;
	}
	return FALSE;
}

static bool auth_passdb_list_have_credentials(struct auth *auth)
{
	struct auth_passdb *passdb;

	for (passdb = auth->passdbs; passdb != NULL; passdb = passdb->next) {
		if (passdb->passdb->iface.lookup_credentials != NULL)
			return TRUE;
	}
	return FALSE;
}

static int auth_passdb_list_have_set_credentials(struct auth *auth)
{
	struct auth_passdb *passdb;

	for (passdb = auth->passdbs; passdb != NULL; passdb = passdb->next) {
		if (passdb->passdb->iface.set_credentials != NULL)
			return TRUE;
	}
	return FALSE;
}

static void auth_mech_list_verify_passdb(struct auth *auth)
{
	struct mech_module_list *list;

	for (list = auth->mech_modules; list != NULL; list = list->next) {
		if (list->module.passdb_need_plain &&
		    !auth_passdb_list_have_plain(auth))
			break;
		if (list->module.passdb_need_credentials &&
                    !auth_passdb_list_have_credentials(auth))
			break;
 		if (list->module.passdb_need_set_credentials &&
 		    !auth_passdb_list_have_set_credentials(auth))
 			break;
	}

	if (list != NULL) {
		if (auth->passdbs == NULL) {
			i_fatal("No passdbs specified in configuration file. "
				"%s mechanism needs one",
				list->module.mech_name);
		}
		i_fatal("%s mechanism can't be supported with given passdbs",
			list->module.mech_name);
	}
}

void auth_init(struct auth *auth)
{
	struct auth_passdb *passdb;
	struct auth_userdb *userdb;
	const struct mech_module *mech;
	const char *const *mechanisms;
	const char *env;

	for (passdb = auth->masterdbs; passdb != NULL; passdb = passdb->next)
		passdb_init(passdb);
	for (passdb = auth->passdbs; passdb != NULL; passdb = passdb->next)
		passdb_init(passdb);
	for (userdb = auth->userdbs; userdb != NULL; userdb = userdb->next)
		userdb_init(userdb);
	passdb_cache_init();

	auth->mech_handshake = str_new(auth->pool, 512);

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

	env = getenv("REALMS");
	if (env == NULL)
		env = "";
	auth->auth_realms = p_strsplit_spaces(auth->pool, env, " ");

	env = getenv("DEFAULT_REALM");
	if (env != NULL && *env != '\0')
		auth->default_realm = env;

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

	env = getenv("USERNAME_FORMAT");
	if (env != NULL && *env != '\0')
		auth->username_format = env;

	env = getenv("GSSAPI_HOSTNAME");
	if (env != NULL && *env != '\0')
		auth->gssapi_hostname = env;
	else
		auth->gssapi_hostname = my_hostname;

	env = getenv("MASTER_USER_SEPARATOR");
	if (env != NULL)
		auth->master_user_separator = env[0];

	auth->ssl_require_client_cert =
		getenv("SSL_REQUIRE_CLIENT_CERT") != NULL;
	auth->ssl_username_from_cert =
		getenv("SSL_USERNAME_FROM_CERT") != NULL;
}

void auth_deinit(struct auth **_auth)
{
        struct auth *auth = *_auth;
	struct auth_passdb *passdb;
	struct auth_userdb *userdb;

	*_auth = NULL;

	for (passdb = auth->masterdbs; passdb != NULL; passdb = passdb->next)
		passdb_deinit(passdb);
	for (passdb = auth->passdbs; passdb != NULL; passdb = passdb->next)
		passdb_deinit(passdb);
	for (userdb = auth->userdbs; userdb != NULL; userdb = userdb->next)
		userdb_deinit(userdb);

	auth_request_handler_deinit();
	passdb_cache_deinit();

	pool_unref(&auth->pool);
}
