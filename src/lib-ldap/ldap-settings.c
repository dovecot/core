/* Copyright (c) 2024 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "settings.h"
#include "ldap-settings.h"
#include "ssl-settings.h"
#include "iostream-ssl.h"

#undef DEF
#undef DEFN
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("ldap_"#name, name, struct ldap_client_settings)
#define DEFN(type, field, name) \
	SETTING_DEFINE_STRUCT_##type(#name, field, struct ldap_client_settings)
static const struct setting_define ldap_client_setting_defines[] = {
	DEF(STR, uris),
	DEF(STR, auth_dn),
	DEF(STR, auth_dn_password),
	DEFN(TIME, timeout_secs, ldap_timeout),
	DEFN(TIME, max_idle_time_secs, ldap_max_idle_time),
	DEF(UINT, debug_level),
	DEF(BOOL, require_ssl),
	DEF(BOOL, starttls),
	SETTING_DEFINE_LIST_END
};

static const struct ldap_client_settings ldap_client_default_settings = {
	.uris = "",
	.auth_dn = "",
	.auth_dn_password = "",
	.timeout_secs = 30,
	.max_idle_time_secs = 0,
	.debug_level = 0,
	.require_ssl = FALSE,
	.starttls = FALSE,
};

const struct setting_parser_info ldap_client_setting_parser_info = {
	.name = "ldap",

	.defines = ldap_client_setting_defines,
	.defaults = &ldap_client_default_settings,

	.struct_size = sizeof(struct ldap_client_settings),
	.pool_offset1 = 1 + offsetof(struct ldap_client_settings, pool),
};

static int
ldap_client_settings_postcheck(struct ldap_client_settings *set, const char **error_r)
{
	if (*set->uris == '\0') {
		*error_r = "ldap_uris not set";
		return -1;
	}

	if (*set->auth_dn == '\0') {
		*error_r = "auth_dn not set";
		return -1;
	}

	if (*set->auth_dn_password == '\0') {
		*error_r = "auth_dn_password not set";
		return -1;
	}

	return 0;
}

static void bind_pool(pool_t to, pool_t from)
{
	pool_add_external_ref(to, from);
	pool_t tmp = from;
	pool_unref(&tmp);
}

int ldap_client_settings_get(struct event *event,
			     const struct ldap_client_settings **set_r,
			     const char **error_r)
{
	struct ldap_client_settings *set = NULL;
	if (settings_get(event, &ldap_client_setting_parser_info, 0, &set, error_r) < 0 ||
	    ldap_client_settings_postcheck(set, error_r) < 0) {
		settings_free(set);
		return -1;
	}

	if (settings_get(event, &ssl_setting_parser_info, 0, &set->ssl_set, error_r) < 0) {
		settings_free(set);
		return -1;
	}

	ssl_client_settings_to_iostream_set(set->ssl_set, &set->ssl_ioset);
	bind_pool(set->pool, set->ssl_set->pool);
	bind_pool(set->pool, set->ssl_ioset->pool);

	*set_r = set;
	*error_r = NULL;
	return 0;
}
