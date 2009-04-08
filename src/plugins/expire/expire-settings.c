/* Copyright (c) 2008-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "settings-parser.h"
#include "mail-storage-settings.h"
#include "expire-settings.h"

#include <stddef.h>
#include <stdlib.h>

#undef DEF
#define DEF(type, name) \
	{ type, #name, offsetof(struct expire_settings, name), NULL }

static struct setting_define expire_setting_defines[] = {
	DEF(SET_STR, base_dir),
	DEF(SET_STR, auth_socket_path),

	{ SET_STRLIST, "plugin", offsetof(struct expire_settings, plugin_envs), NULL },

	SETTING_DEFINE_LIST_END
};

static struct expire_settings expire_default_settings = {
	MEMBER(base_dir) PKG_RUNDIR,
	MEMBER(auth_socket_path) "auth-master"
};

struct setting_parser_info expire_setting_parser_info = {
	MEMBER(defines) expire_setting_defines,
	MEMBER(defaults) &expire_default_settings,

	MEMBER(parent) NULL,
	MEMBER(dynamic_parsers) NULL,

	MEMBER(parent_offset) (size_t)-1,
	MEMBER(type_offset) (size_t)-1,
	MEMBER(struct_size) sizeof(struct expire_settings)
};

static pool_t settings_pool = NULL;

static void fix_base_path(struct expire_settings *set, const char **str)
{
	if (*str != NULL && **str != '\0' && **str != '/') {
		*str = p_strconcat(settings_pool,
				   set->base_dir, "/", *str, NULL);
	}
}

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

void expire_settings_read(const struct expire_settings **set_r,
			  const struct mail_user_settings **user_set_r)
{
	static const struct setting_parser_info *roots[] = {
                &expire_setting_parser_info,
                &mail_user_setting_parser_info
	};
	struct setting_parser_context *parser;
	struct expire_settings *set;
	const char *value;
	void **sets;

	if (settings_pool == NULL)
		settings_pool = pool_alloconly_create("expire settings", 1024);
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

	sets = settings_parser_get_list(parser);
	set = sets[0];
	fix_base_path(set, &set->auth_socket_path);

	*set_r = set;
	*user_set_r = sets[1];
	settings_parser_deinit(&parser);
}
