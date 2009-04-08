/* Copyright (c) 2005-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "hostpid.h"
#include "settings-parser.h"
#include "auth-settings.h"

#include <stddef.h>

extern struct setting_parser_info auth_socket_setting_parser_info;
extern struct setting_parser_info auth_setting_parser_info;
extern struct setting_parser_info auth_root_setting_parser_info;

static bool auth_settings_check(void *_set, pool_t pool, const char **error_r);

#undef DEF
#define DEF(type, name) \
	{ type, #name, offsetof(struct auth_socket_unix_settings, name), NULL }

static struct setting_define auth_socket_client_setting_defines[] = {
	DEF(SET_STR, path),
	DEF(SET_UINT, mode),
	DEF(SET_STR, user),
	DEF(SET_STR, group),

	SETTING_DEFINE_LIST_END
};

static struct auth_socket_unix_settings auth_socket_client_default_settings = {
	MEMBER(path) "auth-client",
	MEMBER(mode) 0660,
	MEMBER(user) "",
	MEMBER(group) ""
};

struct setting_parser_info auth_socket_client_setting_parser_info = {
	MEMBER(defines) auth_socket_client_setting_defines,
	MEMBER(defaults) &auth_socket_client_default_settings,

	MEMBER(parent) &auth_socket_setting_parser_info,
	MEMBER(dynamic_parsers) NULL,

	MEMBER(parent_offset) (size_t)-1,
	MEMBER(type_offset) (size_t)-1,
	MEMBER(struct_size) sizeof(struct auth_socket_unix_settings)
};

#undef DEF
#define DEF(type, name) \
	{ type, #name, offsetof(struct auth_socket_unix_settings, name), NULL }

static struct setting_define auth_socket_master_setting_defines[] = {
	DEF(SET_STR, path),
	DEF(SET_UINT, mode),
	DEF(SET_STR, user),
	DEF(SET_STR, group),

	SETTING_DEFINE_LIST_END
};

static struct auth_socket_unix_settings auth_socket_master_default_settings = {
	MEMBER(path) "auth-master",
	MEMBER(mode) 0660,
	MEMBER(user) "",
	MEMBER(group) ""
};

struct setting_parser_info auth_socket_master_setting_parser_info = {
	MEMBER(defines) auth_socket_master_setting_defines,
	MEMBER(defaults) &auth_socket_master_default_settings,

	MEMBER(parent) &auth_socket_setting_parser_info,
	MEMBER(dynamic_parsers) NULL,

	MEMBER(parent_offset) (size_t)-1,
	MEMBER(type_offset) (size_t)-1,
	MEMBER(struct_size) sizeof(struct auth_socket_unix_settings)
};

#undef DEF
#undef DEFLIST
#define DEF(type, name) \
	{ type, #name, offsetof(struct auth_socket_settings, name), NULL }
#define DEFLIST(field, name, defines) \
	{ SET_DEFLIST, name, offsetof(struct auth_socket_settings, field), defines }

static struct setting_define auth_socket_setting_defines[] = {
	DEF(SET_STR, type),

	DEFLIST(clients, "client", &auth_socket_client_setting_parser_info),
	DEFLIST(masters, "master", &auth_socket_master_setting_parser_info),

	SETTING_DEFINE_LIST_END
};

static struct auth_socket_settings auth_socket_default_settings = {
	MEMBER(type) "listen"
};

struct setting_parser_info auth_socket_setting_parser_info = {
	MEMBER(defines) auth_socket_setting_defines,
	MEMBER(defaults) &auth_socket_default_settings,

	MEMBER(parent) &auth_setting_parser_info,
	MEMBER(dynamic_parsers) NULL,

	MEMBER(parent_offset) (size_t)-1,
	MEMBER(type_offset) offsetof(struct auth_socket_settings, type),
	MEMBER(struct_size) sizeof(struct auth_socket_settings)
};

#undef DEF
#define DEF(type, name) \
	{ type, #name, offsetof(struct auth_passdb_settings, name), NULL }

static struct setting_define auth_passdb_setting_defines[] = {
	DEF(SET_STR, driver),
	DEF(SET_STR, args),
	DEF(SET_BOOL, deny),

	SETTING_DEFINE_LIST_END
};

struct setting_parser_info auth_passdb_setting_parser_info = {
	MEMBER(defines) auth_passdb_setting_defines,
	MEMBER(defaults) NULL,

	MEMBER(parent) &auth_setting_parser_info,
	MEMBER(dynamic_parsers) NULL,

	MEMBER(parent_offset) (size_t)-1,
	MEMBER(type_offset) offsetof(struct auth_passdb_settings, driver),
	MEMBER(struct_size) sizeof(struct auth_passdb_settings)
};

#undef DEF
#define DEF(type, name) \
	{ type, #name, offsetof(struct auth_userdb_settings, name), NULL }

static struct setting_define auth_userdb_setting_defines[] = {
	DEF(SET_STR, driver),
	DEF(SET_STR, args),

	SETTING_DEFINE_LIST_END
};

struct setting_parser_info auth_userdb_setting_parser_info = {
	MEMBER(defines) auth_userdb_setting_defines,
	MEMBER(defaults) NULL,

	MEMBER(parent) &auth_setting_parser_info,
	MEMBER(dynamic_parsers) NULL,

	MEMBER(parent_offset) (size_t)-1,
	MEMBER(type_offset) offsetof(struct auth_userdb_settings, driver),
	MEMBER(struct_size) sizeof(struct auth_userdb_settings)
};

#undef DEF
#undef DEFLIST
#define DEF(type, name) \
	{ type, #name, offsetof(struct auth_settings, name), NULL }
#define DEFLIST(field, name, defines) \
	{ SET_DEFLIST, name, offsetof(struct auth_settings, field), defines }

static struct setting_define auth_setting_defines[] = {
	DEF(SET_STR, name),
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

	DEFLIST(sockets, "socket", &auth_socket_setting_parser_info),
	DEFLIST(passdbs, "passdb", &auth_passdb_setting_parser_info),
	DEFLIST(userdbs, "userdb", &auth_userdb_setting_parser_info),

	SETTING_DEFINE_LIST_END
};

static struct auth_settings auth_default_settings = {
	MEMBER(name) NULL,
	MEMBER(root) NULL,

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

	MEMBER(sockets) ARRAY_INIT,
	MEMBER(passdbs) ARRAY_INIT,
	MEMBER(userdbs) ARRAY_INIT
};

struct setting_parser_info auth_setting_parser_info = {
	MEMBER(defines) auth_setting_defines,
	MEMBER(defaults) &auth_default_settings,

	MEMBER(parent) &auth_root_setting_parser_info,
	MEMBER(dynamic_parsers) NULL,

	MEMBER(parent_offset) offsetof(struct auth_settings, root),
	MEMBER(type_offset) offsetof(struct auth_settings, name),
	MEMBER(struct_size) sizeof(struct auth_settings),
	MEMBER(check_func) auth_settings_check
};

#undef DEF
#undef DEFLIST
#define DEF(type, name) \
	{ type, #name, offsetof(struct auth_root_settings, name), NULL }
#define DEFLIST(field, name, defines) \
	{ SET_DEFLIST, name, offsetof(struct auth_root_settings, field), defines }

static struct setting_define auth_root_setting_defines[] = {
	DEF(SET_STR, base_dir),
	DEFLIST(auths, "auth", &auth_setting_parser_info),

	SETTING_DEFINE_LIST_END
};

static struct auth_root_settings auth_root_default_settings = {
	MEMBER(base_dir) PKG_RUNDIR,
	MEMBER(auths) ARRAY_INIT
};

struct setting_parser_info auth_root_setting_parser_info = {
	MEMBER(defines) auth_root_setting_defines,
	MEMBER(defaults) &auth_root_default_settings,

	MEMBER(parent) NULL,
	MEMBER(dynamic_parsers) NULL,

	MEMBER(parent_offset) (size_t)-1,
	MEMBER(type_offset) (size_t)-1,
	MEMBER(struct_size) sizeof(struct auth_root_settings)
};

static pool_t settings_pool = NULL;

static void fix_base_path(struct auth_settings *set, const char **str)
{
	if (*str != NULL && **str != '\0' && **str != '/') {
		*str = p_strconcat(settings_pool,
				   set->root->base_dir, "/", *str, NULL);
	}
}

/* <settings checks> */
static bool auth_settings_check(void *_set ATTR_UNUSED, pool_t pool ATTR_UNUSED,
				const char **error_r ATTR_UNUSED)
{
#ifndef CONFIG_BINARY
	struct auth_settings *set = _set;
	struct auth_socket_unix_settings *const *u;
	struct auth_socket_settings *const *sockets;
	unsigned int i, j, count, count2;

	if (!array_is_created(&set->sockets))
		return TRUE;

	sockets = array_get(&set->sockets, &count);
	for (i = 0; i < count; i++) {
		if (array_is_created(&sockets[i]->masters)) {
			u = array_get(&sockets[i]->masters, &count2);
			for (j = 0; j < count2; j++)
				fix_base_path(set, &u[j]->path);
		}
		if (array_is_created(&sockets[i]->clients)) {
			u = array_get(&sockets[i]->clients, &count2);
			for (j = 0; j < count2; j++)
				fix_base_path(set, &u[j]->path);
		}
	}
#endif
	return TRUE;
}
/* </settings checks> */

struct auth_settings *auth_settings_read(const char *name)
{
	struct setting_parser_context *parser;
	struct auth_root_settings *set;
	struct auth_settings *const *auths;
	const char *error;
	unsigned int i, count;

	if (settings_pool == NULL)
		settings_pool = pool_alloconly_create("auth settings", 1024);
	else
		p_clear(settings_pool);

	parser = settings_parser_init(settings_pool,
				      &auth_root_setting_parser_info,
				      SETTINGS_PARSER_FLAG_IGNORE_UNKNOWN_KEYS);

	auth_default_settings.gssapi_hostname = my_hostname;

	if (settings_parse_environ(parser) < 0) {
		i_fatal("Error reading configuration: %s",
			settings_parser_get_error(parser));
	}

	if (settings_parser_check(parser, settings_pool, &error) < 0)
		i_fatal("Invalid settings: %s", error);

	set = settings_parser_get(parser);
	settings_parser_deinit(&parser);

	if (array_is_created(&set->auths)) {
		auths = array_get(&set->auths, &count);
		for (i = 0; i < count; i++) {
			if (strcmp(auths[i]->name, name) == 0)
				return auths[i];
		}
	}
	i_fatal("Error reading configuration: No auth section: %s", name);
	return NULL;
}
