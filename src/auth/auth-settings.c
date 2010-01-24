/* Copyright (c) 2005-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "settings-parser.h"
#include "master-service-settings.h"
#include "service-settings.h"
#include "auth-settings.h"

#include <stddef.h>

extern const struct setting_parser_info auth_setting_parser_info;
extern const struct setting_parser_info auth_root_setting_parser_info;

static bool auth_settings_check(void *_set, pool_t pool, const char **error_r);
static bool auth_passdb_settings_check(void *_set, pool_t pool, const char **error_r);
static bool auth_userdb_settings_check(void *_set, pool_t pool, const char **error_r);

/* <settings checks> */
static struct file_listener_settings auth_unix_listeners_array[] = {
	{ "login/auth", 0666, "", "" },
	{ "auth-userdb", 0600, "", "" },
	{ "auth-master", 0600, "", "" }
};
static struct file_listener_settings *auth_unix_listeners[] = {
	&auth_unix_listeners_array[0],
	&auth_unix_listeners_array[1],
	&auth_unix_listeners_array[2]
};
static buffer_t auth_unix_listeners_buf = {
	auth_unix_listeners, sizeof(auth_unix_listeners), { 0, }
};
/* </settings checks> */

struct service_settings auth_service_settings = {
	.name = "auth",
	.protocol = "",
	.type = "",
	.executable = "auth",
	.user = "",
	.group = "",
	.privileged_group = "",
	.extra_groups = "",
	.chroot = "",

	.drop_priv_before_exec = FALSE,

	.process_min_avail = 0,
	.process_limit = 1,
	.client_limit = 0,
	.service_count = 0,
	.vsz_limit = -1U,

	.unix_listeners = { { &auth_unix_listeners_buf,
			      sizeof(auth_unix_listeners[0]) } },
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT
};

/* <settings checks> */
static struct file_listener_settings auth_worker_unix_listeners_array[] = {
	{ "auth-worker", 0600, "", "" }
};
static struct file_listener_settings *auth_worker_unix_listeners[] = {
	&auth_worker_unix_listeners_array[0]
};
static buffer_t auth_worker_unix_listeners_buf = {
	auth_worker_unix_listeners, sizeof(auth_worker_unix_listeners), { 0, }
};
/* </settings checks> */

struct service_settings auth_worker_service_settings = {
	.name = "auth-worker",
	.protocol = "",
	.type = "",
	.executable = "auth -w",
	.user = "",
	.group = "",
	.privileged_group = "",
	.extra_groups = "",
	.chroot = "",

	.drop_priv_before_exec = FALSE,

	.process_min_avail = 0,
	.process_limit = 0,
	.client_limit = 1,
	.service_count = 0,
	.vsz_limit = -1U,

	.unix_listeners = { { &auth_worker_unix_listeners_buf,
			      sizeof(auth_worker_unix_listeners[0]) } },
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT
};

#undef DEF
#define DEF(type, name) \
	{ type, #name, offsetof(struct auth_passdb_settings, name), NULL }

static const struct setting_define auth_passdb_setting_defines[] = {
	DEF(SET_STR, driver),
	DEF(SET_STR, args),
	DEF(SET_BOOL, deny),
	DEF(SET_BOOL, pass),
	DEF(SET_BOOL, master),

	SETTING_DEFINE_LIST_END
};

const struct setting_parser_info auth_passdb_setting_parser_info = {
	.defines = auth_passdb_setting_defines,

	.type_offset = (size_t)-1,
	.struct_size = sizeof(struct auth_passdb_settings),

	.parent_offset = (size_t)-1,
	.parent = &auth_setting_parser_info,

	.check_func = auth_passdb_settings_check
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
	.defines = auth_userdb_setting_defines,

	.type_offset = (size_t)-1,
	.struct_size = sizeof(struct auth_userdb_settings),

	.parent_offset = (size_t)-1,
	.parent = &auth_setting_parser_info,

	.check_func = auth_userdb_settings_check
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
	DEF(SET_SIZE, cache_size),
	DEF(SET_TIME, cache_ttl),
	DEF(SET_TIME, cache_negative_ttl),
	DEF(SET_STR, username_chars),
	DEF(SET_STR, username_translation),
	DEF(SET_STR, username_format),
	DEF(SET_STR, master_user_separator),
	DEF(SET_STR, anonymous_username),
	DEF(SET_STR, krb5_keytab),
	DEF(SET_STR, gssapi_hostname),
	DEF(SET_STR, winbind_helper_path),
	DEF(SET_TIME, failure_delay),

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
	.mechanisms = "plain",
	.realms = "",
	.default_realm = "",
	.cache_size = 0,
	.cache_ttl = 60*60,
	.cache_negative_ttl = 0,
	.username_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890.-_@",
	.username_translation = "",
	.username_format = "",
	.master_user_separator = "",
	.anonymous_username = "anonymous",
	.krb5_keytab = "",
	.gssapi_hostname = "",
	.winbind_helper_path = "/usr/bin/ntlm_auth",
	.failure_delay = 2,

	.verbose = FALSE,
	.debug = FALSE,
	.debug_passwords = FALSE,
	.ssl_require_client_cert = FALSE,
	.ssl_username_from_cert = FALSE,
	.use_winbind = FALSE,

	.worker_max_count = 30,

	.passdbs = ARRAY_INIT,
	.userdbs = ARRAY_INIT
};

const struct setting_parser_info auth_setting_parser_info = {
	.module_name = "auth",
	.defines = auth_setting_defines,
	.defaults = &auth_default_settings,

	.type_offset = (size_t)-1,
	.struct_size = sizeof(struct auth_settings),

	.parent_offset = (size_t)-1,

	.check_func = auth_settings_check
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

static bool
auth_passdb_settings_check(void *_set, pool_t pool ATTR_UNUSED,
			   const char **error_r)
{
	struct auth_passdb_settings *set = _set;

	if (set->driver == NULL || *set->driver == '\0') {
		*error_r = "passdb is missing driver";
		return FALSE;
	}
	return TRUE;
}

static bool
auth_userdb_settings_check(void *_set, pool_t pool ATTR_UNUSED,
			   const char **error_r)
{
	struct auth_userdb_settings *set = _set;

	if (set->driver == NULL || *set->driver == '\0') {
		*error_r = "passdb is missing driver";
		return FALSE;
	}
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
