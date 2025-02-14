/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "array.h"
#include "settings.h"
#include "mech.h"
#include "userdb.h"
#include "passdb.h"
#include "auth.h"
#include "dns-lookup.h"

#define AUTH_DNS_SOCKET_PATH "dns-client"
#define AUTH_DNS_DEFAULT_TIMEOUT_MSECS (1000*10)
#define AUTH_DNS_IDLE_TIMEOUT_MSECS (1000*60)
#define AUTH_DNS_CACHE_TTL_SECS 10

bool shutting_down = FALSE;

struct event *auth_event;
struct event_category event_category_auth = {
	.name = "auth",
};

static const struct auth_userdb_settings userdb_dummy_set = {
	.name = "",
	.driver = "static",

	.skip = "never",
	.result_success = "return-ok",
	.result_failure = "continue",
	.result_internalfail = "continue",
};

ARRAY_TYPE(auth) auths;

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
auth_passdb_preinit(struct auth *auth, const struct auth_passdb_settings *_set,
		    struct auth_passdb **passdbs)
{
	struct auth_passdb *auth_passdb, **dest;
	const struct auth_passdb_settings *set;
	const char *error;

	/* Lookup passdb-specific auth_settings */
	struct event *event = event_create(auth_event);
	event_add_str(event, "protocol", auth->protocol);
	event_add_str(event, "passdb", _set->name);
	settings_event_add_filter_name(event,
		t_strconcat("passdb_", _set->driver, NULL));
	settings_event_add_list_filter_name(event, "passdb", _set->name);
	set = settings_get_or_fatal(event, &auth_passdb_setting_parser_info);

	auth_passdb = p_new(auth->pool, struct auth_passdb, 1);
	auth_passdb->auth_set =
		settings_get_or_fatal(event, &auth_setting_parser_info);
	if (settings_get(event, &auth_passdb_post_setting_parser_info,
			 SETTINGS_GET_FLAG_NO_CHECK |
			 SETTINGS_GET_FLAG_NO_EXPAND,
			 &auth_passdb->unexpanded_post_set, &error) < 0)
		i_fatal("%s", error);

	auth_passdb->name = set->name;
	auth_passdb->set = set;
	auth_passdb->skip = auth_passdb_skip_parse(set->skip);
	auth_passdb->result_success =
		auth_db_rule_parse(set->result_success);
	auth_passdb->result_failure =
		auth_db_rule_parse(set->result_failure);
	auth_passdb->result_internalfail =
		auth_db_rule_parse(set->result_internalfail);

	if (!array_is_created(&set->mechanisms_filter) ||
	    array_is_empty(&set->mechanisms_filter)) {
		auth_passdb->mechanisms_filter = NULL;
	} else {
		auth_passdb->mechanisms_filter =
			settings_boollist_get(&set->mechanisms_filter);
	}

	if (*set->username_filter == '\0') {
		auth_passdb->username_filter = NULL;
	} else {
		auth_passdb->username_filter =
			(const char *const *)p_strsplit_spaces(auth->pool,
				set->username_filter, " ,");
	}

	for (dest = passdbs; *dest != NULL; dest = &(*dest)->next) ;
	*dest = auth_passdb;

	auth_passdb->passdb = passdb_preinit(auth->pool, event, set);
	if (auth_passdb->passdb->default_cache_key != NULL && set->use_cache) {
		auth_passdb->cache_key = auth_passdb->passdb->default_cache_key;
	} else {
		auth_passdb->cache_key = NULL;
	}
	event_unref(&event);
}

static void auth_passdb_deinit(struct auth_passdb *passdb)
{
	passdb_deinit(passdb->passdb);
	settings_free(passdb->set);
	settings_free(passdb->auth_set);
	settings_free(passdb->unexpanded_post_set);
}

static void
auth_userdb_preinit(struct auth *auth, const struct auth_userdb_settings *_set)
{
	struct auth_userdb *auth_userdb, **dest;
	const struct auth_userdb_settings *set;
	const char *error;

	/* Lookup userdb-specific auth_settings */
	struct event *event = event_create(auth_event);
	event_add_str(event, "protocol", auth->protocol);
	event_add_str(event, "userdb", _set->name);
	settings_event_add_filter_name(event,
		t_strconcat("userdb_", _set->driver, NULL));
	settings_event_add_list_filter_name(event, "userdb", _set->name);
	if (_set == &userdb_dummy_set) {
		/* If this is the dummy set do not try to lookup settings. */
		set = _set;
	} else {
		set = settings_get_or_fatal(event,
					    &auth_userdb_setting_parser_info);
	}

	auth_userdb = p_new(auth->pool, struct auth_userdb, 1);
	auth_userdb->auth_set =
		settings_get_or_fatal(event, &auth_setting_parser_info);
	if (settings_get(event, &auth_userdb_post_setting_parser_info,
			 SETTINGS_GET_FLAG_NO_CHECK |
			 SETTINGS_GET_FLAG_NO_EXPAND,
			 &auth_userdb->unexpanded_post_set, &error) < 0)
		i_fatal("%s", error);

	auth_userdb->name = set->name;
	auth_userdb->set = set;
	auth_userdb->skip = auth_userdb_skip_parse(set->skip);
	auth_userdb->result_success =
		auth_db_rule_parse(set->result_success);
	auth_userdb->result_failure =
		auth_db_rule_parse(set->result_failure);
	auth_userdb->result_internalfail =
		auth_db_rule_parse(set->result_internalfail);

	for (dest = &auth->userdbs; *dest != NULL; dest = &(*dest)->next) ;
	*dest = auth_userdb;

	auth_userdb->userdb = userdb_preinit(auth->pool, event, set);
	if (auth_userdb->userdb->default_cache_key != NULL && set->use_cache) {
		auth_userdb->cache_key = auth_userdb->userdb->default_cache_key;
	} else {
		auth_userdb->cache_key = NULL;
	}
	event_unref(&event);
}

static void auth_userdb_deinit(struct auth_userdb *userdb)
{
	if (userdb->set != &userdb_dummy_set)
		settings_free(userdb->set);
	settings_free(userdb->auth_set);
	settings_free(userdb->unexpanded_post_set);
	userdb_deinit(userdb->userdb);
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
auth_preinit(const struct auth_settings *set, const char *protocol,
	     const struct mechanisms_register *reg)
{
	const struct auth_passdb_settings *const *passdbs;
	const struct auth_userdb_settings *const *userdbs;
	struct auth *auth;
	unsigned int i, count, db_count, passdb_count, last_passdb = 0;

	pool_t pool = pool_alloconly_create("auth", 128);
	auth = p_new(pool, struct auth, 1);
	auth->pool = pool;
	auth->protocol = p_strdup(pool, protocol);
	auth->protocol_set = set;
	pool_ref(set->pool);
	auth->reg = reg;

	if (array_is_created(&set->parsed_passdbs))
		passdbs = array_get(&set->parsed_passdbs, &db_count);
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
	if (passdb_count != 0 &&
	     strcmp(passdbs[last_passdb]->result_success, "continue") == 0)
		i_fatal("Last passdb can't have result_success=continue");

	for (i = 0; i < db_count; i++) {
		if (!passdbs[i]->master)
			continue;

		/* skip skip=unauthenticated, as explained above */
		if (auth->masterdbs == NULL &&
		    auth_passdb_skip_parse(passdbs[i]->skip) == AUTH_PASSDB_SKIP_UNAUTHENTICATED)
			continue;

		if (passdbs[i]->deny)
			i_fatal("Master passdb can't have deny=yes");
		if (passdb_count == 0 &&
		    strcmp(passdbs[i]->result_success, "continue") == 0) {
			i_fatal("Master passdb can't have result_success=continue "
				"if there are no passdbs");
		}
		auth_passdb_preinit(auth, passdbs[i], &auth->masterdbs);
	}

	if (array_is_created(&set->parsed_userdbs)) {
		userdbs = array_get(&set->parsed_userdbs, &count);
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
	struct dns_lookup_settings dns_set;

	for (passdb = auth->masterdbs; passdb != NULL; passdb = passdb->next)
		auth_passdb_init(passdb);
	for (passdb = auth->passdbs; passdb != NULL; passdb = passdb->next)
		auth_passdb_init(passdb);
	for (userdb = auth->userdbs; userdb != NULL; userdb = userdb->next)
		userdb_init(userdb->userdb);

	i_zero(&dns_set);
	dns_set.dns_client_socket_path = AUTH_DNS_SOCKET_PATH;
	dns_set.timeout_msecs = AUTH_DNS_DEFAULT_TIMEOUT_MSECS;
	dns_set.idle_timeout_msecs = AUTH_DNS_IDLE_TIMEOUT_MSECS;
	dns_set.cache_ttl_secs = AUTH_DNS_CACHE_TTL_SECS;

	auth->dns_client = dns_client_init(&dns_set);
}

static void auth_deinit(struct auth *auth)
{
	struct auth_passdb *passdb;
	struct auth_userdb *userdb;

	for (passdb = auth->masterdbs; passdb != NULL; passdb = passdb->next)
		auth_passdb_deinit(passdb);
	for (passdb = auth->passdbs; passdb != NULL; passdb = passdb->next)
		auth_passdb_deinit(passdb);
	for (userdb = auth->userdbs; userdb != NULL; userdb = userdb->next)
		auth_userdb_deinit(userdb);

	dns_client_deinit(&auth->dns_client);
}

static void
auth_passdbs_update_md5(struct auth *auth, struct md5_context *ctx)
{
	struct auth_passdb *passdb;
	unsigned int hash;

	for (passdb = auth->passdbs; passdb != NULL; passdb = passdb->next) {
		md5_update(ctx, &passdb->passdb->id, sizeof(passdb->passdb->id));
		hash = settings_hash(&auth_passdb_setting_parser_info,
				     passdb->set, NULL);
		md5_update(ctx, &hash, sizeof(hash));
		hash = settings_hash(&auth_setting_parser_info,
				     passdb->auth_set, NULL);
		md5_update(ctx, &hash, sizeof(hash));
		hash = settings_hash(&auth_passdb_post_setting_parser_info,
				     passdb->unexpanded_post_set, NULL);
		md5_update(ctx, &hash, sizeof(hash));
	}
}

void auth_passdbs_generate_md5(unsigned char md5[STATIC_ARRAY MD5_RESULTLEN])
{
	struct auth *auth;
	struct md5_context ctx;

	md5_init(&ctx);
	array_foreach_elem(&auths, auth)
		auth_passdbs_update_md5(auth, &ctx);
	md5_final(&ctx, md5);
}

static void
auth_userdbs_update_md5(struct auth *auth, struct md5_context *ctx)
{
	struct auth_userdb *userdb;
	unsigned int hash;

	for (userdb = auth->userdbs; userdb != NULL; userdb = userdb->next) {
		md5_update(ctx, &userdb->userdb->id, sizeof(userdb->userdb->id));
		hash = settings_hash(&auth_userdb_setting_parser_info,
				     userdb->set, NULL);
		md5_update(ctx, &hash, sizeof(hash));
		hash = settings_hash(&auth_setting_parser_info,
				     userdb->auth_set, NULL);
		md5_update(ctx, &hash, sizeof(hash));
		hash = settings_hash(&auth_userdb_post_setting_parser_info,
				     userdb->unexpanded_post_set, NULL);
		md5_update(ctx, &hash, sizeof(hash));
	}
}

void auth_userdbs_generate_md5(unsigned char md5[STATIC_ARRAY MD5_RESULTLEN])
{
	struct auth *auth;
	struct md5_context ctx;

	md5_init(&ctx);
	array_foreach_elem(&auths, auth)
		auth_userdbs_update_md5(auth, &ctx);
	md5_final(&ctx, md5);
}

struct auth *auth_find_protocol(const char *name)
{
	struct auth *const *a;
	unsigned int i, count;

	a = array_get(&auths, &count);
	if (name != NULL) {
		for (i = 1; i < count; i++) {
			if (strcmp(a[i]->protocol, name) == 0)
				return a[i];
		}
		/* not found. maybe we can instead find a !protocol */
		for (i = 1; i < count; i++) {
			if (a[i]->protocol[0] == '!' &&
			    strcmp(a[i]->protocol + 1, name) != 0)
				return a[i];
		}
	}
	return a[0];
}

struct auth *auth_default_protocol(void)
{
	struct auth *const *a;
	unsigned int count;

	a = array_get(&auths, &count);
	return a[0];
}

void auths_preinit(struct event *parent_event,
		   const struct auth_settings *set,
		   const struct mechanisms_register *reg,
		   const char *const *protocols)
{
	const struct auth_settings *protocol_set;
	struct auth *auth;
	unsigned int i;
	const char *not_protocol = NULL;
	bool check_default = TRUE;

	auth_event = event_create(parent_event);
	event_set_forced_debug(auth_event, set->debug);
	event_add_category(auth_event, &event_category_auth);
	i_array_init(&auths, 8);

	auth = auth_preinit(set, NULL, reg);
	array_push_back(&auths, &auth);

	for (i = 0; protocols[i] != NULL; i++) {
		if (protocols[i][0] == '!') {
			if (not_protocol != NULL) {
				i_fatal("Can't have multiple !protocols "
					"(seen %s and %s)",
					not_protocol, protocols[i]);
			}
			not_protocol = protocols[i];
		}
		protocol_set = auth_settings_get(protocols[i]);
		auth = auth_preinit(protocol_set, protocols[i], reg);
		array_push_back(&auths, &auth);
		settings_free(protocol_set);
	}

	if (not_protocol != NULL && str_array_find(protocols, not_protocol+1))
		check_default = FALSE;

	array_foreach_elem(&auths, auth) {
		if (auth->protocol != NULL || check_default)
			auth_mech_list_verify_passdb(auth);
	}
}

void auths_init(void)
{
	struct auth *auth;

	/* sanity checks */
	i_assert(*auth_request_var_expand_static_tab[AUTH_REQUEST_VAR_TAB_USER_IDX].key == 'u');
	i_assert(auth_request_var_expand_static_tab[AUTH_REQUEST_VAR_TAB_COUNT].key == NULL);
	i_assert(auth_request_var_expand_static_tab[AUTH_REQUEST_VAR_TAB_COUNT-1].key != NULL);

	array_foreach_elem(&auths, auth)
		auth_init(auth);
}

void auths_deinit(void)
{
	struct auth *auth;

	array_foreach_elem(&auths, auth)
		auth_deinit(auth);
	event_unref(&auth_event);
}

void auths_free(void)
{
	struct auth *auth;

	array_foreach_elem(&auths, auth) {
		settings_free(auth->protocol_set);
		pool_unref(&auth->pool);
	}
	array_free(&auths);
}
