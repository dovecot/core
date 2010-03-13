/* Copyright (c) 2005-2010 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "network.h"
#include "array.h"
#include "str.h"
#include "env-util.h"
#include "mech.h"
#include "userdb.h"
#include "passdb.h"
#include "passdb-cache.h"
#include "auth.h"
#include "auth-request-handler.h"

#include <stdlib.h>
#include <unistd.h>

struct auth_userdb_settings userdb_dummy_set = {
	.driver = "static",
	.args = ""
};

static ARRAY_DEFINE(auths, struct auth *);

static void
auth_passdb_preinit(struct auth *auth, const struct auth_passdb_settings *set)
{
	struct auth_passdb *auth_passdb, **dest;

	auth_passdb = p_new(auth->pool, struct auth_passdb, 1);
	auth_passdb->set = set;

	for (dest = &auth->passdbs; *dest != NULL; dest = &(*dest)->next) ;
	*dest = auth_passdb;

	auth_passdb->passdb =
		passdb_preinit(auth->pool, set->driver, set->args);
}

static void
auth_userdb_preinit(struct auth *auth, const struct auth_userdb_settings *set)
{
        struct auth_userdb *auth_userdb, **dest;

	auth_userdb = p_new(auth->pool, struct auth_userdb, 1);
	auth_userdb->set = set;

	for (dest = &auth->userdbs; *dest != NULL; dest = &(*dest)->next) ;
	*dest = auth_userdb;

	auth_userdb->userdb =
		userdb_preinit(auth->pool, set->driver, set->args);
}

struct auth *
auth_preinit(const struct auth_settings *set, const char *service,
	     const struct mechanisms_register *reg)
{
	struct auth_passdb_settings *const *passdbs;
	struct auth_userdb_settings *const *userdbs;
	struct auth *auth;
	pool_t pool;
	unsigned int i, count, db_count, passdb_count, last_passdb = 0;

	pool = pool_alloconly_create("auth", 2048);
	auth = p_new(pool, struct auth, 1);
	auth->pool = pool;
	auth->service = p_strdup(pool, service);
	auth->set = set;
	auth->reg = reg;

	if (array_is_created(&set->passdbs))
		passdbs = array_get(&set->passdbs, &db_count);
	else {
		passdbs = NULL;
		db_count = 0;
	}

	/* initialize passdbs first and count them */
	for (passdb_count = 0, i = 0; i < db_count; i++) {
		if (passdbs[i]->master)
			continue;

		auth_passdb_preinit(auth, passdbs[i]);
		passdb_count++;
		last_passdb = i;
	}
	if (passdb_count != 0 && passdbs[last_passdb]->pass)
		i_fatal("Last passdb can't have pass=yes");

	for (i = 0; i < db_count; i++) {
		if (!passdbs[i]->master)
			continue;

		if (passdbs[i]->deny)
			i_fatal("Master passdb can't have deny=yes");
		if (passdbs[i]->pass && passdb_count == 0) {
			i_fatal("Master passdb can't have pass=yes "
				"if there are no passdbs");
		}
		auth_passdb_preinit(auth, passdbs[i]);
	}

	if (array_is_created(&set->userdbs)) {
		userdbs = array_get(&set->userdbs, &count);
		for (i = 0; i < count; i++)
			auth_userdb_preinit(auth, userdbs[i]);
	}

	if (auth->userdbs == NULL) {
		/* use a dummy userdb static. */
		auth_userdb_preinit(auth, &userdb_dummy_set);
	}
	return auth;
}

static bool auth_passdb_list_have_verify_plain(struct auth *auth)
{
	struct auth_passdb *passdb;

	for (passdb = auth->passdbs; passdb != NULL; passdb = passdb->next) {
		if (passdb->passdb->iface.verify_plain != NULL)
			return TRUE;
	}
	return FALSE;
}

static bool auth_passdb_list_have_lookup_credentials(struct auth *auth)
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

static bool
auth_mech_verify_passdb(struct auth *auth, struct mech_module_list *list)
{
	switch (list->module.passdb_need) {
	case MECH_PASSDB_NEED_NOTHING:
		break;
	case MECH_PASSDB_NEED_VERIFY_PLAIN:
		if (!auth_passdb_list_have_verify_plain(auth))
			return FALSE;
		break;
	case MECH_PASSDB_NEED_VERIFY_RESPONSE:
	case MECH_PASSDB_NEED_LOOKUP_CREDENTIALS:
		if (!auth_passdb_list_have_lookup_credentials(auth))
			return FALSE;
		break;
	case MECH_PASSDB_NEED_SET_CREDENTIALS:
		if (!auth_passdb_list_have_lookup_credentials(auth))
			return FALSE;
		if (!auth_passdb_list_have_set_credentials(auth))
			return FALSE;
		break;
	}
	return TRUE;
}

static void auth_mech_list_verify_passdb(struct auth *auth)
{
	struct mech_module_list *list;

	for (list = auth->reg->modules; list != NULL; list = list->next) {
		if (!auth_mech_verify_passdb(auth, list))
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

	for (passdb = auth->masterdbs; passdb != NULL; passdb = passdb->next)
		passdb_init(passdb->passdb);
	for (passdb = auth->passdbs; passdb != NULL; passdb = passdb->next)
		passdb_init(passdb->passdb);
	for (userdb = auth->userdbs; userdb != NULL; userdb = userdb->next)
		userdb_init(userdb->userdb);

	/* caching is handled only by the main auth process */
	if (!worker)
		passdb_cache_init(auth->set);

	auth_mech_list_verify_passdb(auth);
}

void auth_deinit(struct auth **_auth)
{
        struct auth *auth = *_auth;
	struct auth_passdb *passdb;
	struct auth_userdb *userdb;

	*_auth = NULL;

	for (passdb = auth->masterdbs; passdb != NULL; passdb = passdb->next)
		passdb_deinit(passdb->passdb);
	for (passdb = auth->passdbs; passdb != NULL; passdb = passdb->next)
		passdb_deinit(passdb->passdb);
	for (userdb = auth->userdbs; userdb != NULL; userdb = userdb->next)
		userdb_deinit(userdb->userdb);

	auth_request_handler_deinit();
	passdb_cache_deinit();

	pool_unref(&auth->pool);
}

struct auth *auth_find_service(const char *name)
{
	struct auth *const *a;
	unsigned int i, count;

	a = array_get(&auths, &count);
	if (name != NULL) {
		for (i = 1; i < count; i++) {
			if (strcmp(a[i]->service, name) == 0)
				return a[i];
		}
	}
	return a[0];
}

void auths_preinit(const struct auth_settings *set,
		   const struct mechanisms_register *reg)
{
	static const char *services[] = {
		"imap", "pop3", "lda", "lmtp", "managesieve"
	};
	const struct auth_settings *service_set;
	struct auth *auth;
	unsigned int i;

	i_array_init(&auths, 8);

	auth = auth_preinit(set, NULL, reg);
	array_append(&auths, &auth, 1);

	/* FIXME: this is ugly.. the service names should be coming from
	   the first config lookup */
	for (i = 0; i < N_ELEMENTS(services); i++) {
		service_set = auth_settings_read(services[i]);
		auth = auth_preinit(service_set, services[i], reg);
		array_append(&auths, &auth, 1);
	}
}

void auths_init(void)
{
	struct auth *const *auth;

	array_foreach(&auths, auth)
		auth_init(*auth);
}

void auths_deinit(void)
{
	struct auth **auth;
	unsigned int i, count;

	/* deinit in reverse order, because modules have been allocated by
	   the first auth pool that used them */
	auth = array_get_modifiable(&auths, &count);
	for (i = count; i > 0; i--)
		auth_deinit(&auth[i-1]);
	array_free(&auths);
}
