/* Copyright (c) 2005-2008 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "settings-parser.h"
#include "mail-storage-settings.h"
#include "imap-settings.h"

#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>

static bool imap_settings_check(void *_set, pool_t pool, const char **error_r);

#undef DEF
#undef DEFLIST
#define DEF(type, name) \
	{ type, #name, offsetof(struct imap_settings, name), NULL }
#define DEFLIST(field, name, defines) \
	{ SET_DEFLIST, name, offsetof(struct imap_settings, field), defines }

static struct setting_define imap_setting_defines[] = {
	DEF(SET_STR, base_dir),
	DEF(SET_STR, auth_socket_path),

	DEF(SET_BOOL, mail_debug),
	DEF(SET_BOOL, shutdown_clients),
	DEF(SET_BOOL, verbose_proctitle),

	DEF(SET_STR, mail_plugins),
	DEF(SET_STR, mail_plugin_dir),

	DEF(SET_UINT, imap_max_line_length),
	DEF(SET_STR, imap_capability),
	DEF(SET_STR, imap_client_workarounds),
	DEF(SET_STR, imap_logout_format),
	DEF(SET_STR, imap_id_send),
	DEF(SET_STR, imap_id_log),

	SETTING_DEFINE_LIST_END
};

static struct imap_settings imap_default_settings = {
	MEMBER(base_dir) PKG_RUNDIR,
	MEMBER(auth_socket_path) "auth-master",

	MEMBER(mail_debug) FALSE,
	MEMBER(shutdown_clients) FALSE,
	MEMBER(verbose_proctitle) FALSE,

	MEMBER(mail_plugins) "",
	MEMBER(mail_plugin_dir) MODULEDIR,

	/* RFC-2683 recommends at least 8000 bytes. Some clients however don't
	   break large message sets to multiple commands, so we're pretty
	   liberal by default. */
	MEMBER(imap_max_line_length) 65536,
	MEMBER(imap_capability) "",
	MEMBER(imap_client_workarounds) "outlook-idle",
	MEMBER(imap_logout_format) "bytes=%i/%o",
	MEMBER(imap_id_send) "",
	MEMBER(imap_id_log) ""
};

struct setting_parser_info imap_setting_parser_info = {
	MEMBER(defines) imap_setting_defines,
	MEMBER(defaults) &imap_default_settings,

	MEMBER(parent) NULL,
	MEMBER(dynamic_parsers) NULL,

	MEMBER(parent_offset) (size_t)-1,
	MEMBER(type_offset) (size_t)-1,
	MEMBER(struct_size) sizeof(struct imap_settings),
	MEMBER(check_func) imap_settings_check
};

static pool_t settings_pool = NULL;

static void fix_base_path(struct imap_settings *set, const char **str)
{
	if (*str != NULL && **str != '\0' && **str != '/') {
		*str = p_strconcat(settings_pool,
				   set->base_dir, "/", *str, NULL);
	}
}

/* <settings checks> */
static bool imap_settings_check(void *_set, pool_t pool ATTR_UNUSED,
				const char **error_r)
{
	struct imap_settings *set = _set;

#ifndef CONFIG_BINARY
	fix_base_path(set, &set->auth_socket_path);
#endif

	if (*set->mail_plugins != '\0' &&
	    access(set->mail_plugin_dir, R_OK | X_OK) < 0) {
		*error_r = t_strdup_printf(
			"mail_plugin_dir: access(%s) failed: %m",
			set->mail_plugin_dir);
		return FALSE;
	}
	return TRUE;
}
/* </settings checks> */

static void
parse_expand_vars(struct setting_parser_context *parser, const char *value)
{
	const char *const *expanded;

	expanded = t_strsplit(value, " ");
	settings_parse_set_keys_expandeded(parser, settings_pool, expanded);
	/* settings from userdb are in the VARS_EXPANDED list. for each
	   unknown setting in the list assume it's a plugin setting. */
	for (; *expanded != NULL; expanded++) {
		if (settings_parse_is_valid_key(parser, *expanded))
			continue;

		value = getenv(t_str_ucase(*expanded));
		if (value == NULL)
			continue;

		settings_parse_line(parser, t_strconcat("plugin/", *expanded,
							"=", value, NULL));
	}
}

void imap_settings_read(const struct imap_settings **set_r,
			const struct mail_user_settings **user_set_r)
{
	static const struct setting_parser_info *roots[] = {
                &imap_setting_parser_info,
                &mail_user_setting_parser_info
	};
	struct setting_parser_context *parser;
	const char *value, *error;
	void **sets;

	if (settings_pool == NULL)
		settings_pool = pool_alloconly_create("imap settings", 2048);
	else
		p_clear(settings_pool);

	mail_storage_namespace_defines_init(settings_pool);

	parser = settings_parser_init_list(settings_pool,
				roots, N_ELEMENTS(roots),
				SETTINGS_PARSER_FLAG_IGNORE_UNKNOWN_KEYS);

	if (settings_parse_environ(parser) < 0) {
		i_fatal("Error reading configuration: %s",
			settings_parser_get_error(parser));
	}

	value = getenv("VARS_EXPANDED");
	if (value != NULL)
		parse_expand_vars(parser, value);

	if (settings_parser_check(parser, settings_pool, &error) < 0)
		i_fatal("Invalid settings: %s", error);

	sets = settings_parser_get_list(parser);
	*set_r = sets[0];
	*user_set_r = sets[1];
	settings_parser_deinit(&parser);
}
