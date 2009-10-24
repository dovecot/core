/* Copyright (c) 2005-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "settings-parser.h"
#include "master-service-settings.h"
#include "auth-settings.h"

#include <stddef.h>

extern const struct setting_parser_info auth_setting_parser_info;
extern const struct setting_parser_info auth_root_setting_parser_info;

static bool auth_settings_check(void *_set, pool_t pool, const char **error_r);

#undef DEF
#define DEF(type, name) \
	{ type, #name, offsetof(struct auth_passdb_settings, name), NULL }

static const struct setting_define auth_passdb_setting_defines[] = {
	DEF(SET_STR, driver),
	DEF(SET_STR, args),
	DEF(SET_BOOL, deny),

	SETTING_DEFINE_LIST_END
};

const struct setting_parser_info auth_passdb_setting_parser_info = {
	MEMBER(module_name) NULL,
	MEMBER(defines) auth_passdb_setting_defines,
	MEMBER(defaults) NULL,

	MEMBER(type_offset) offsetof(struct auth_passdb_settings, driver),
	MEMBER(struct_size) sizeof(struct auth_passdb_settings),

	MEMBER(parent_offset) (size_t)-1,
	MEMBER(parent) &auth_setting_parser_info
};

#undef DEF
#define DEF(type, name) \
	{ type, #name, offsetof(struct auth_userdb_settings, name), NULL }

static const struct setting_define auth_userdb_setting_defines[] = {
	DEF(SET_STR, driver),
	DEF(SET_STR, args),

	SETTING_DEFINE_LIST_END
};

const struct setting_parser_info auth_userdb_setting_parser_info = {
	MEMBER(module_name) NULL,
	MEMBER(defines) auth_userdb_setting_defines,
	MEMBER(defaults) NULL,

	MEMBER(type_offset) offsetof(struct auth_userdb_settings, driver),
	MEMBER(struct_size) sizeof(struct auth_userdb_settings),

	MEMBER(parent_offset) (size_t)-1,
	MEMBER(parent) &auth_setting_parser_info
};

/* we're kind of kludging here to avoid "auth_" prefix in the struct fields */
#undef DEF
#undef DEFLIST
#define DEF(type, name) \
	{ type, "auth_"#name, offsetof(struct auth_settings, name), NULL }
#define DEFLIST(field, name, defines) \
	{ SET_DEFLIST, name, offsetof(struct auth_settings, field), defines }

static const struct setting_define auth_setting_defines[] = {
	DEF(SET_STR, mechanisms),
	DEF(SET_STR, realms),
	DEF(SET_STR, default_realm),
	DEF(SET_UINT, cache_size),
	DEF(SET_UINT, cache_ttl),
	DEF(SET_UINT, cache_negative_ttl),
	DEF(SET_STR, username_chars),
	DEF(SET_STR, username_translation),
	DEF(SET_STR, username_format),
	DEF(SET_STR, master_user_separator),
	DEF(SET_STR, anonymous_username),
	DEF(SET_STR, krb5_keytab),
	DEF(SET_STR, gssapi_hostname),
	DEF(SET_STR, winbind_helper_path),
	DEF(SET_UINT, failure_delay),

	DEF(SET_BOOL, verbose),
	DEF(SET_BOOL, debug),
	DEF(SET_BOOL, debug_passwords),
	DEF(SET_BOOL, ssl_require_client_cert),
	DEF(SET_BOOL, ssl_username_from_cert),
	DEF(SET_BOOL, use_winbind),

	DEF(SET_UINT, worker_max_count),

	DEFLIST(passdbs, "passdb", &auth_passdb_setting_parser_info),
	DEFLIST(userdbs, "userdb", &auth_userdb_setting_parser_info),

	SETTING_DEFINE_LIST_END
};

static const struct auth_settings auth_default_settings = {
	MEMBER(mechanisms) "plain",
	MEMBER(realms) "",
	MEMBER(default_realm) "",
	MEMBER(cache_size) 0,
	MEMBER(cache_ttl) 3600,
	MEMBER(cache_negative_ttl) 0,
	MEMBER(username_chars) "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890.-_@",
	MEMBER(username_translation) "",
	MEMBER(username_format) "",
	MEMBER(master_user_separator) "",
	MEMBER(anonymous_username) "anonymous",
	MEMBER(krb5_keytab) "",
	MEMBER(gssapi_hostname) "",
	MEMBER(winbind_helper_path) "/usr/bin/ntlm_auth",
	MEMBER(failure_delay) 2,

	MEMBER(verbose) FALSE,
	MEMBER(debug) FALSE,
	MEMBER(debug_passwords) FALSE,
	MEMBER(ssl_require_client_cert) FALSE,
	MEMBER(ssl_username_from_cert) FALSE,
	MEMBER(use_winbind) FALSE,

	MEMBER(worker_max_count) 30,

	MEMBER(passdbs) ARRAY_INIT,
	MEMBER(userdbs) ARRAY_INIT
};

const struct setting_parser_info auth_setting_parser_info = {
	MEMBER(module_name) "auth",
	MEMBER(defines) auth_setting_defines,
	MEMBER(defaults) &auth_default_settings,

	MEMBER(type_offset) (size_t)-1,
	MEMBER(struct_size) sizeof(struct auth_settings),

	MEMBER(parent_offset) (size_t)-1,
	MEMBER(parent) NULL,

	MEMBER(check_func) auth_settings_check
};

/* <settings checks> */
static bool auth_settings_check(void *_set, pool_t pool ATTR_UNUSED,
				const char **error_r ATTR_UNUSED)
{
	struct auth_settings *set = _set;

	if (set->debug_passwords)
		set->debug = TRUE;
	if (set->debug)
		set->verbose = TRUE;
	return TRUE;
}
/* </settings checks> */

struct auth_settings *
auth_settings_read(struct master_service *service)
{
	static const struct setting_parser_info *set_roots[] = {
		&auth_setting_parser_info,
		NULL
	};
	const char *error;
	void **sets;

	if (master_service_settings_read_simple(service, set_roots, &error) < 0)
		i_fatal("Error reading configuration: %s", error);

	sets = master_service_settings_get_others(service);
	return sets[0];
}
