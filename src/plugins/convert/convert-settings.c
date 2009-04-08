/* Copyright (c) 2008-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "settings-parser.h"
#include "mail-storage-settings.h"
#include "convert-settings.h"

#include <stddef.h>
#include <stdlib.h>

#undef DEF
#define DEF(type, name) \
	{ type, #name, offsetof(struct convert_settings, name), NULL }

static struct setting_define convert_setting_defines[] = {
	DEF(SET_STR, base_dir),
	DEF(SET_STR, auth_socket_path),

	{ SET_STRLIST, "plugin", offsetof(struct convert_settings, plugin_envs), NULL },

	SETTING_DEFINE_LIST_END
};

static struct convert_settings convert_default_settings = {
	MEMBER(base_dir) PKG_RUNDIR,
	MEMBER(auth_socket_path) "auth-master"
};

struct setting_parser_info convert_setting_parser_info = {
	MEMBER(defines) convert_setting_defines,
	MEMBER(defaults) &convert_default_settings,

	MEMBER(parent) NULL,
	MEMBER(dynamic_parsers) NULL,

	MEMBER(parent_offset) (size_t)-1,
	MEMBER(type_offset) (size_t)-1,
	MEMBER(struct_size) sizeof(struct convert_settings)
};

static pool_t settings_pool = NULL;

static void fix_base_path(struct convert_settings *set, const char **str)
{
	if (*str != NULL && **str != '\0' && **str != '/') {
		*str = p_strconcat(settings_pool,
				   set->base_dir, "/", *str, NULL);
	}
}

void convert_settings_read(const struct convert_settings **set_r,
			   const struct mail_user_settings **user_set_r)
{
	static const struct setting_parser_info *roots[] = {
                &convert_setting_parser_info,
                &mail_user_setting_parser_info
	};
	struct setting_parser_context *parser;
	struct convert_settings *set;
	void **sets;

	if (settings_pool == NULL)
		settings_pool = pool_alloconly_create("convert settings", 1024);
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

	sets = settings_parser_get_list(parser);
	set = sets[0];
	fix_base_path(set, &set->auth_socket_path);

	*set_r = set;
	*user_set_r = sets[1];
	settings_parser_deinit(&parser);
}
