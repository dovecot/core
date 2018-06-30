/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "array.h"
#include "settings-parser.h"
#include "master-service-settings.h"
#include "mech.h"
#include "userdb.h"
#include "passdb.h"
#include "passdb-template.h"
#include "userdb-template.h"
#include "auth.h"

struct event *auth_event;
struct event_category event_category_auth = {
	.name = "auth",
};

static const struct auth_userdb_settings userdb_dummy_set = {
	.name = "",
	.driver = "static",
	.args = "",
	.default_fields = "",
	.override_fields = "",

	.skip = "never",
	.result_success = "return-ok",
	.result_failure = "continue",
	.result_internalfail = "continue"
};

static ARRAY(struct auth *) auths;

static enum auth_passdb_skip auth_passdb_skip_parse(const char *str)
{
	if (strcmp(str, "never") == 0)
		return AUTH_PASSDB_SKIP_NEVER;
	if (strcmp(str, "authenticated") == 0)
		return AUTH_PASSDB_SKIP_AUTHENTICATED;
	if (strcmp(str, "unauthenticated") == 0)
		return AUTH_PASSDB_SKIP_UNAUTHENTICATED;
	i_unreached();
}

static enum auth_userdb_skip auth_userdb_skip_parse(const char *str)
{
	if (strcmp(str, "never") == 0)
		return AUTH_USERDB_SKIP_NEVER;
	if (strcmp(str, "found") == 0)
		return AUTH_USERDB_SKIP_FOUND;
	if (strcmp(str, "notfound") == 0)
		return AUTH_USERDB_SKIP_NOTFOUND;
	i_unreached();
}

static enum auth_db_rule auth_db_rule_parse(const char *str)
{
	if (strcmp(str, "return") == 0)
		return AUTH_DB_RULE_RETURN;
	if (strcmp(str, "return-ok") == 0)
		return AUTH_DB_RULE_RETURN_OK;
	if (strcmp(str, "return-fail") == 0)
		return AUTH_DB_RULE_RETURN_FAIL;
	if (strcmp(str, "continue") == 0)
		return AUTH_DB_RULE_CONTINUE;
	if (strcmp(str, "continue-ok") == 0)
		return AUTH_DB_RULE_CONTINUE_OK;
	if (strcmp(str, "continue-fail") == 0)
		return AUTH_DB_RULE_CONTINUE_FAIL;
	i_unreached();
}

static void
auth_passdb_preinit(struct auth *auth, const struct auth_passdb_settings *set,
		    struct auth_passdb **passdbs)
{
	struct auth_passdb *auth_passdb, **dest;

	auth_passdb = p_new(auth->pool, struct auth_passdb, 1);
	auth_passdb->set = set;
	auth_passdb->skip = auth_passdb_skip_parse(set->skip);
	auth_passdb->result_success =
		auth_db_rule_parse(set->result_success);
	auth_passdb->result_failure =
		auth_db_rule_parse(set->result_failure);
	auth_passdb->result_internalfail =
		auth_db_rule_parse(set->result_internalfail);

	auth_passdb->default_fields_tmpl =
		passdb_template_build(auth->pool, set->default_fields);
	auth_passdb->override_fields_tmpl =
		passdb_template_build(auth->pool, set->override_fields);

	/* for backwards compatibility: */
	if (set->pass)
		auth_passdb->result_success = AUTH_DB_RULE_CONTINUE;

	for (dest = passdbs; *dest != NULL; dest = &(*dest)->next) ;
	*dest = auth_passdb;

	auth_passdb->passdb = passdb_preinit(auth->pool, set);
	/* make sure any %variables in default_fields exist in cache_key */
	if (auth_passdb->passdb->default_cache_key != NULL) {
		auth_passdb->cache_key =
			p_strconcat(auth->pool, auth_passdb->passdb->default_cache_key,
				set->default_fields, NULL);
	}
	else {
		auth_passdb->cache_key = NULL;
	}
}

static void
auth_userdb_preinit(struct auth *auth, const struct auth_userdb_settings *set)
{
        struct auth_userdb *auth_userdb, **dest;

	auth_userdb = p_new(auth->pool, struct auth_userdb, 1);
	auth_userdb->set = set;
	auth_userdb->skip = auth_userdb_skip_parse(set->skip);
	auth_userdb->result_success =
		auth_db_rule_parse(set->result_success);
	auth_userdb->result_failure =
		auth_db_rule_parse(set->result_failure);
	auth_userdb->result_internalfail =
		auth_db_rule_parse(set->result_internalfail);

	auth_userdb->default_fields_tmpl =
		userdb_template_build(auth->pool, set->driver,
				      set->default_fields);
	auth_userdb->override_fields_tmpl =
		userdb_template_build(auth->pool, set->driver,
				      set->override_fields);

	for (dest = &auth->userdbs; *dest != NULL; dest = &(*dest)->next) ;
	*dest = auth_userdb;

	auth_userdb->userdb = userdb_preinit(auth->pool, set);
	/* make sure any %variables in default_fields exist in cache_key */
	if (auth_userdb->userdb->default_cache_key != NULL) {
		auth_userdb->cache_key =
			p_strconcat(auth->pool, auth_userdb->userdb->default_cache_key,
				    set->default_fields, NULL);
	}
	else {
		auth_userdb->cache_key = NULL;
	}
}

static bool auth_passdb_list_have_verify_plain(const struct auth *auth)
{
	const struct auth_passdb *passdb;

	for (passdb = auth->passdbs; passdb != NULL; passdb = passdb->next) {
		if (passdb->passdb->iface.verify_plain != NULL)
			return TRUE;
	}
	return FALSE;
}

static bool auth_passdb_list_have_lookup_credentials(const struct auth *auth)
{
	const struct auth_passdb *passdb;

	for (passdb = auth->passdbs; passdb != NULL; passdb = passdb->next) {
		if (passdb->passdb->iface.lookup_credentials != NULL)
			return TRUE;
	}
	return FALSE;
}

static bool auth_passdb_list_have_set_credentials(const struct auth *auth)
{
	const struct auth_passdb *passdb;

	for (passdb = auth->masterdbs; passdb != NULL; passdb = passdb->next) {
		if (passdb->passdb->iface.set_credentials != NULL)
			return TRUE;
	}
	for (passdb = auth->passdbs; passdb != NULL; passdb = passdb->next) {
		if (passdb->passdb->iface.set_credentials != NULL)
			return TRUE;
	}
	return FALSE;
}

static bool
auth_mech_verify_passdb(const struct auth *auth, const struct mech_module_list *list)
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

static void auth_mech_list_verify_passdb(const struct auth *auth)
{
	const struct mech_module_list *list;

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

static struct auth * ATTR_NULL(2)
auth_preinit(const struct auth_settings *set, const char *service, pool_t pool,
	     const struct mechanisms_register *reg)
{
	struct auth_passdb_settings *const *passdbs;
	struct auth_userdb_settings *const *userdbs;
	struct auth *auth;
	unsigned int i, count, db_count, passdb_count, last_passdb = 0;

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

		/* passdb { skip=unauthenticated } as the first passdb doesn't
		   make sense, since user is never authenticated at that point.
		   skip over them silently. */
		if (auth->passdbs == NULL &&
		    auth_passdb_skip_parse(passdbs[i]->skip) == AUTH_PASSDB_SKIP_UNAUTHENTICATED)
			continue;

		auth_passdb_preinit(auth, passdbs[i], &auth->passdbs);
		passdb_count++;
		last_passdb = i;
	}
	if (passdb_count != 0 && passdbs[last_passdb]->pass)
		i_fatal("Last passdb can't have pass=yes");

	for (i = 0; i < db_count; i++) {
		if (!passdbs[i]->master)
			continue;

		/* skip skip=unauthenticated, as explained above */
		if (auth->masterdbs == NULL &&
		    auth_passdb_skip_parse(passdbs[i]->skip) == AUTH_PASSDB_SKIP_UNAUTHENTICATED)
			continue;

		if (passdbs[i]->deny)
			i_fatal("Master passdb can't have deny=yes");
		if (passdbs[i]->pass && passdb_count == 0) {
			i_fatal("Master passdb can't have pass=yes "
				"if there are no passdbs");
		}
		auth_passdb_preinit(auth, passdbs[i], &auth->masterdbs);
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

static void auth_passdb_init(struct auth_passdb *passdb)
{
	passdb_init(passdb->passdb);

	i_assert(passdb->passdb->default_pass_scheme != NULL ||
		 passdb->cache_key == NULL);
}

static void auth_init(struct auth *auth)
{
	struct auth_passdb *passdb;
	struct auth_userdb *userdb;

	for (passdb = auth->masterdbs; passdb != NULL; passdb = passdb->next)
		auth_passdb_init(passdb);
	for (passdb = auth->passdbs; passdb != NULL; passdb = passdb->next)
		auth_passdb_init(passdb);
	for (userdb = auth->userdbs; userdb != NULL; userdb = userdb->next)
		userdb_init(userdb->userdb);
}

static void auth_deinit(struct auth *auth)
{
	struct auth_passdb *passdb;
	struct auth_userdb *userdb;

	for (passdb = auth->masterdbs; passdb != NULL; passdb = passdb->next)
		passdb_deinit(passdb->passdb);
	for (passdb = auth->passdbs; passdb != NULL; passdb = passdb->next)
		passdb_deinit(passdb->passdb);
	for (userdb = auth->userdbs; userdb != NULL; userdb = userdb->next)
		userdb_deinit(userdb->userdb);
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
		/* not found. maybe we can instead find a !service */
		for (i = 1; i < count; i++) {
			if (a[i]->service[0] == '!' &&
			    strcmp(a[i]->service + 1, name) != 0)
				return a[i];
		}
	}
	return a[0];
}

struct auth *auth_default_service(void)
{
	struct auth *const *a;
	unsigned int count;

	a = array_get(&auths, &count);
	return a[0];
}

void auths_preinit(const struct auth_settings *set, pool_t pool,
		   const struct mechanisms_register *reg,
		   const char *const *services)
{
	struct master_service_settings_output set_output;
	const struct auth_settings *service_set;
	struct auth *auth, *const *authp;
	unsigned int i;
	const char *not_service = NULL;
	bool check_default = TRUE;

	auth_event = event_create(NULL);
	event_set_forced_debug(auth_event, set->debug);
	event_add_category(auth_event, &event_category_auth);
	i_array_init(&auths, 8);

	auth = auth_preinit(set, NULL, pool, reg);
	array_append(&auths, &auth, 1);

	for (i = 0; services[i] != NULL; i++) {
		if (services[i][0] == '!') {
			if (not_service != NULL) {
				i_fatal("Can't have multiple protocol "
					"!services (seen %s and %s)",
					not_service, services[i]);
			}
			not_service = services[i];
		}
		service_set = auth_settings_read(services[i], pool,
						 &set_output);
		auth = auth_preinit(service_set, services[i], pool, reg);
		array_append(&auths, &auth, 1);
	}

	if (not_service != NULL && str_array_find(services, not_service+1))
		check_default = FALSE;

	array_foreach(&auths, authp) {
		if ((*authp)->service != NULL || check_default)
			auth_mech_list_verify_passdb(*authp);
	}
}

void auths_init(void)
{
	struct auth *const *auth;

	/* sanity checks */
	i_assert(auth_request_var_expand_static_tab[AUTH_REQUEST_VAR_TAB_USER_IDX].key == 'u');
	i_assert(auth_request_var_expand_static_tab[AUTH_REQUEST_VAR_TAB_USERNAME_IDX].key == 'n');
	i_assert(auth_request_var_expand_static_tab[AUTH_REQUEST_VAR_TAB_DOMAIN_IDX].key == 'd');
	i_assert(auth_request_var_expand_static_tab[AUTH_REQUEST_VAR_TAB_COUNT].key == '\0' &&
		 auth_request_var_expand_static_tab[AUTH_REQUEST_VAR_TAB_COUNT].long_key == NULL);
	i_assert(auth_request_var_expand_static_tab[AUTH_REQUEST_VAR_TAB_COUNT-1].key != '\0' ||
		 auth_request_var_expand_static_tab[AUTH_REQUEST_VAR_TAB_COUNT-1].long_key != NULL);

	array_foreach(&auths, auth)
		auth_init(*auth);
}

void auths_deinit(void)
{
	struct auth *const *auth;

	array_foreach(&auths, auth)
		auth_deinit(*auth);
	event_unref(&auth_event);
}

void auths_free(void)
{
	struct auth **auth;
	unsigned int i, count;

	/* deinit in reverse order, because modules have been allocated by
	   the first auth pool that used them */
	auth = array_get_modifiable(&auths, &count);
	for (i = count; i > 0; i--)
		pool_unref(&auth[i-1]->pool);
	array_free(&auths);
}
