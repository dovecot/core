/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "array.h"
#include "version.h"
#include "settings.h"
#include "settings-history.h"
#include "config-parser-private.h"
#include "old-set-parser.h"

static bool has_config_version(const char *dovecot_config_version)
{
	return dovecot_config_version[0] != '\0' &&
		/* 0.0.0 is for git builds - it's always the latest */
		strcmp(dovecot_config_version, "0.0.0") != 0;
}

static void ATTR_FORMAT(2, 3)
obsolete(struct config_parser_context *ctx, const char *str, ...)
{
	static bool seen_obsoletes = FALSE;
	va_list args;

	if ((ctx->flags & CONFIG_PARSE_FLAG_HIDE_OBSOLETE_WARNINGS) != 0)
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

/* Returns TRUE if the setting was replaced by another setting with a
   different value. */
static bool old_settings_handle_value(struct config_parser_context *ctx,
				      struct config_line *line)
{
	struct settings_history *history = settings_history_get();
	const struct setting_history_value *value;

	array_foreach(&history->values, value) {
		if (version_cmp(value->version,
				ctx->dovecot_config_version) <= 0)
			break;
		if (strcmp(value->old_key, line->key) == 0 &&
		    strcasecmp(value->old_value, line->value) == 0) {
			obsolete(ctx, "%s=%s has been replaced by %s=%s",
				 value->old_key, value->old_value,
				 value->new_key, value->new_value);
			line->key = value->new_key;
			line->value = value->new_value;
			return TRUE;
		}
	}
	return FALSE;
}

static const char *
old_settings_cur_filter_name(struct config_parser_context *ctx)
{
	const char *filter_name =
		ctx->cur_section->filter_parser->filter.filter_name;

	if (filter_name == NULL)
		return NULL;
	if (filter_name[0] == SETTINGS_INCLUDE_GROUP_PREFIX)
		filter_name++;
	return filter_name;
}

static const char *
old_settings_rename_new_key(struct config_parser_context *ctx,
			    const char *new_key)
{
	const char *filter_name = old_settings_cur_filter_name(ctx);
	const char *suffix;

	/* The new key may have a filter prefix, e.g.
	   imapc/client_auth_authzid. If the setting already is inside that
	   filter, drop the prefix - otherwise a nested filter with the same
	   name would be created. */
	if (filter_name != NULL &&
	    str_begins(new_key, t_strconcat(filter_name, "/", NULL), &suffix))
		return suffix;
	return new_key;
}

static void old_settings_handle_rename(struct config_parser_context *ctx,
				       struct config_line *line)
{
	struct settings_history *history = settings_history_get();
	const struct setting_history_rename *rename;
	const char *filter_name = old_settings_cur_filter_name(ctx);
	const char *old_keys[3];
	unsigned int i, old_keys_count = 0;

	/* The setting may be written with its full name, but inside a named
	   filter it may also be written without the filter name prefix, e.g.
	   imapc { user = .. } instead of imapc_user. Check the same key
	   candidates as the autoprefixing in config_parser_apply_line(). */
	old_keys[old_keys_count++] = line->key;
	if (filter_name != NULL) {
		old_keys[old_keys_count++] = t_strdup_printf("%s_%s",
			t_str_replace(filter_name, '/', '_'), line->key);
		if (strchr(filter_name, '/') != NULL) {
			old_keys[old_keys_count++] = t_strdup_printf("%s_%s",
				t_strcut(filter_name, '/'), line->key);
		}
	}

	array_foreach(&history->renames, rename) {
		if (version_cmp(rename->version,
				ctx->dovecot_config_version) <= 0)
			break;
		for (i = 0; i < old_keys_count; i++) {
			if (strcmp(rename->old_key, old_keys[i]) != 0)
				continue;
			obsolete(ctx, "%s has been renamed to %s",
				 rename->old_key, rename->new_key);
			line->key = old_settings_rename_new_key(ctx,
								rename->new_key);
			return;
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
		if (!has_config_version(ctx->dovecot_config_version))
			break;
		if (!old_settings_handle_value(ctx, line))
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
	const char *generic_value = NULL;

	if (!has_config_version(dovecot_config_version))
		return FALSE;

	array_foreach(&history->defaults, def) {
		if (version_cmp(def->version, dovecot_config_version) <= 0)
			break;
		if (strcmp(def->key, key_with_path) == 0) {
			/* Exact filter path match is the most specific and
			   always wins over a match on just the setting name. */
			*old_default_r = def->old_value;
			return TRUE;
		}
		if (generic_value == NULL && strcmp(def->key, key) == 0)
			generic_value = def->old_value;
	}
	if (generic_value != NULL) {
		*old_default_r = generic_value;
		return TRUE;
	}
	return FALSE;
}

unsigned int
old_settings_default_changes_count(const char *dovecot_config_version)
{
	struct settings_history *history = settings_history_get();
	const struct setting_history_default *def;
	unsigned int count = 0;

	if (!has_config_version(dovecot_config_version))
		return 0;

	array_foreach(&history->defaults, def) {
		if (version_cmp(def->version, dovecot_config_version) <= 0)
			break;
		count++;
	}
	return count;
}
