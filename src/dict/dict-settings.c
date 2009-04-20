/* Copyright (c) 2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "settings-parser.h"
#include "dict-settings.h"

#undef DEF
#define DEF(type, name) \
	{ type, #name, offsetof(struct dict_settings, name), NULL }

static struct setting_define dict_setting_defines[] = {
	DEF(SET_STR, dict_db_config),
	{ SET_STRLIST, "dict", offsetof(struct dict_settings, dicts), NULL },

	SETTING_DEFINE_LIST_END
};

struct dict_settings dict_default_settings = {
	MEMBER(dict_db_config) "",
	MEMBER(dicts) ARRAY_INIT
};

struct setting_parser_info dict_setting_parser_info = {
	MEMBER(defines) dict_setting_defines,
	MEMBER(defaults) &dict_default_settings,

	MEMBER(parent) NULL,
	MEMBER(dynamic_parsers) NULL,

	MEMBER(parent_offset) (size_t)-1,
	MEMBER(type_offset) (size_t)-1,
	MEMBER(struct_size) sizeof(struct dict_settings)
};

struct dict_settings *dict_settings;

static pool_t settings_pool = NULL;

struct dict_settings *dict_settings_read(void)
{
	struct setting_parser_context *parser;
	struct dict_settings *set;
	const char *error;

	if (settings_pool == NULL)
		settings_pool = pool_alloconly_create("auth settings", 1024);
	else
		p_clear(settings_pool);

	parser = settings_parser_init(settings_pool,
				      &dict_setting_parser_info,
				      SETTINGS_PARSER_FLAG_IGNORE_UNKNOWN_KEYS);

	if (settings_parse_environ(parser) < 0) {
		i_fatal("Error reading configuration: %s",
			settings_parser_get_error(parser));
	}

	if (settings_parser_check(parser, settings_pool, &error) < 0)
		i_fatal("Invalid settings: %s", error);

	set = settings_parser_get(parser);
	settings_parser_deinit(&parser);
	return set;
}
