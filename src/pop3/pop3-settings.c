/* Copyright (c) 2005-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "settings-parser.h"
#include "mail-storage-settings.h"
#include "pop3-settings.h"

#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>

#undef DEF
#undef DEFLIST
#define DEF(type, name) \
	{ type, #name, offsetof(struct pop3_settings, name), NULL }
#define DEFLIST(field, name, defines) \
	{ SET_DEFLIST, name, offsetof(struct pop3_settings, field), defines }

static struct setting_define pop3_setting_defines[] = {
	DEF(SET_BOOL, mail_debug),
	DEF(SET_BOOL, shutdown_clients),
	DEF(SET_BOOL, verbose_proctitle),

	DEF(SET_BOOL, pop3_no_flag_updates),
	DEF(SET_BOOL, pop3_enable_last),
	DEF(SET_BOOL, pop3_reuse_xuidl),
	DEF(SET_BOOL, pop3_lock_session),
	DEF(SET_STR, pop3_client_workarounds),
	DEF(SET_STR, pop3_logout_format),
	DEF(SET_STR, pop3_uidl_format),

	SETTING_DEFINE_LIST_END
};

static struct pop3_settings pop3_default_settings = {
	MEMBER(mail_debug) FALSE,
	MEMBER(shutdown_clients) FALSE,
	MEMBER(verbose_proctitle) FALSE,

	MEMBER(pop3_no_flag_updates) FALSE,
	MEMBER(pop3_enable_last) FALSE,
	MEMBER(pop3_reuse_xuidl) FALSE,
	MEMBER(pop3_lock_session) FALSE,
	MEMBER(pop3_client_workarounds) NULL,
	MEMBER(pop3_logout_format) "top=%t/%p, retr=%r/%b, del=%d/%m, size=%s",
	MEMBER(pop3_uidl_format) "%08Xu%08Xv"
};

struct setting_parser_info pop3_setting_parser_info = {
	MEMBER(defines) pop3_setting_defines,
	MEMBER(defaults) &pop3_default_settings,

	MEMBER(parent) NULL,
	MEMBER(dynamic_parsers) NULL,

	MEMBER(parent_offset) (size_t)-1,
	MEMBER(type_offset) (size_t)-1,
	MEMBER(struct_size) sizeof(struct pop3_settings),
	MEMBER(check_func) NULL
};

static pool_t settings_pool = NULL;

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

void pop3_settings_read(const struct pop3_settings **set_r,
			const struct mail_user_settings **user_set_r)
{
	static const struct setting_parser_info *roots[] = {
                &pop3_setting_parser_info,
                &mail_user_setting_parser_info
	};
	struct setting_parser_context *parser;
	const char *value, *error;
	void **sets;

	if (settings_pool == NULL)
		settings_pool = pool_alloconly_create("pop3 settings", 1024);
	else
		p_clear(settings_pool);

	settings_parser_info_update(settings_pool,
				    mail_storage_get_dynamic_parsers());

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
