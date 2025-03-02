/* Copyright (c) 2009-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "master-service.h"
#include "settings-history.h"
#include "config-parser-private.h"
#include "old-set-parser.h"

static void ATTR_FORMAT(2, 3)
obsolete(struct config_parser_context *ctx, const char *str, ...)
{
	static bool seen_obsoletes = FALSE;
	va_list args;

	if (ctx->hide_obsolete_warnings)
		return;

	if (!seen_obsoletes) {
		i_warning("NOTE: You can get a new clean config file with: "
			  "doveconf -Pn > dovecot-new.conf");
		seen_obsoletes = TRUE;
	}

	va_start(args, str);
	i_warning("Obsolete setting in %s:%u: %s",
		  ctx->cur_input->path, ctx->cur_input->linenum,
		  t_strdup_vprintf(str, args));
	va_end(args);
}

static void old_settings_handle_rename(struct config_parser_context *ctx,
				       struct config_line *line)
{
	struct settings_history *history = settings_history_get();
	const struct setting_history_rename *rename;

	if (ctx->dovecot_config_version[0] == '\0')
		return;

	array_foreach(&history->renames, rename) {
		if (version_cmp(rename->version,
				ctx->dovecot_config_version) <= 0)
			break;
		if (strcmp(rename->old_key, line->key) == 0) {
			obsolete(ctx, "%s has been renamed to %s",
				 rename->old_key, rename->new_key);
			line->key = rename->new_key;
			break;
		}
	}
}

void old_settings_handle(struct config_parser_context *ctx,
			 struct config_line *line)
{
	switch (line->type) {
	case CONFIG_LINE_TYPE_SKIP:
	case CONFIG_LINE_TYPE_CONTINUE:
	case CONFIG_LINE_TYPE_ERROR:
	case CONFIG_LINE_TYPE_INCLUDE:
	case CONFIG_LINE_TYPE_INCLUDE_TRY:
	case CONFIG_LINE_TYPE_SECTION_BEGIN:
	case CONFIG_LINE_TYPE_SECTION_END:
	case CONFIG_LINE_TYPE_GROUP_SECTION_BEGIN:
		break;
	case CONFIG_LINE_TYPE_KEYFILE:
	case CONFIG_LINE_TYPE_KEYVALUE:
	case CONFIG_LINE_TYPE_KEYVARIABLE:
		old_settings_handle_rename(ctx, line);
		break;
	}
}

bool old_settings_default(const char *dovecot_config_version,
			  const char *key, const char *key_with_path,
			  const char **old_default_r)
{
	struct settings_history *history = settings_history_get();
	const struct setting_history_default *def;

	if (dovecot_config_version[0] == '\0')
		return FALSE;

	array_foreach(&history->defaults, def) {
		if (version_cmp(def->version, dovecot_config_version) <= 0)
			break;
		if (strcmp(def->key, key) == 0 ||
		    strcmp(def->key, key_with_path) == 0) {
			*old_default_r = def->old_value;
			return TRUE;
		}
	}
	return FALSE;
}

unsigned int
old_settings_default_changes_count(const char *dovecot_config_version)
{
	struct settings_history *history = settings_history_get();
	const struct setting_history_default *def;
	unsigned int count = 0;

	array_foreach(&history->defaults, def) {
		if (version_cmp(def->version, dovecot_config_version) <= 0)
			break;
		count++;
	}
	return count;
}
