/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "hash.h"
#include "ostream.h"
#include "settings-parser.h"
#include "master-service-settings.h"
#include "all-settings.h"
#include "config-parser.h"
#include "config-request.h"
#include "config-filter.h"
#include "old-set-parser.h"

struct config_export_context {
	pool_t pool;
	string_t *value;
	HASH_TABLE(const char *, const char *) keys;
	enum config_dump_scope scope;
	const char *dovecot_config_version;
	const char *path_prefix;

	config_request_callback_t *callback;
	void *context;

	enum config_dump_flags flags;
	const struct config_module_parser *module_parsers;
};

static void config_export_size(string_t *str, uoff_t size)
{
	static const char suffixes[] = { 'B', 'k', 'M', 'G', 'T' };
	char suffix = suffixes[0];
	unsigned int i;

	if (size == 0) {
		str_append_c(str, '0');
		return;
	}
	if (size == SET_SIZE_UNLIMITED) {
		str_append(str, SET_VALUE_UNLIMITED);
		return;
	}
	for (i = 1; i < N_ELEMENTS(suffixes) && (size % 1024) == 0; i++) {
		suffix = suffixes[i];
		size /= 1024;
	}
	str_printfa(str, "%"PRIuUOFF_T" %c", size, suffix);
}

static void config_export_time(string_t *str, unsigned int stamp)
{
	const char *suffix = "secs";

	if (stamp == 0) {
		str_append_c(str, '0');
		return;
	}
	if (stamp == SET_TIME_INFINITE) {
		str_append(str, SET_VALUE_INFINITE);
		return;
	}

	if (stamp % 60 == 0) {
		stamp /= 60;
		suffix = "mins";
		if (stamp % 60 == 0) {
			stamp /= 60;
			suffix = "hours";
			if (stamp % 24 == 0) {
				stamp /= 24;
				suffix = "days";
				if (stamp % 7 == 0) {
					stamp /= 7;
					suffix = "weeks";
				}
			}
		}
	}

	str_printfa(str, "%u %s", stamp, suffix);
}

static void config_export_time_msecs(string_t *str, unsigned int stamp_msecs)
{
	if (stamp_msecs == SET_TIME_MSECS_INFINITE)
		str_append(str, SET_VALUE_INFINITE);
	else if ((stamp_msecs % 1000) == 0)
		config_export_time(str, stamp_msecs/1000);
	else
		str_printfa(str, "%u ms", stamp_msecs);
}

bool config_export_type(string_t *str, const void *value,
			enum setting_type type)
{
	switch (type) {
	case SET_BOOL: {
		const bool *val = value;

		str_append(str, *val ? "yes" : "no");
		break;
	}
	case SET_SIZE: {
		const uoff_t *val = value;

		config_export_size(str, *val);
		break;
	}
	case SET_UINTMAX: {
		const uint64_t *val = value;
		str_printfa(str, "%ju", *val);
		break;
	}
	case SET_UINT:
	case SET_UINT_OCT: {
		const unsigned int *val = value;
		if (*val == SET_UINT_UNLIMITED) {
			str_append(str, SET_VALUE_UNLIMITED);
			break;
		}
		if (type == SET_UINT_OCT)
			str_printfa(str, "0%o", *val);
		else
			str_printfa(str, "%u", *val);
		break;
	}
	case SET_TIME:
	case SET_TIME_MSECS: {
		const unsigned int *val = value;

		if (type == SET_TIME)
			config_export_time(str, *val);
		else
			config_export_time_msecs(str, *val);
		break;
	}
	case SET_IN_PORT: {
		const in_port_t *val = value;

		str_printfa(str, "%u", *val);
		break;
	}
	case SET_STR:
	case SET_STR_NOVARS:
	case SET_FILE:
	case SET_ENUM: {
		const char *const *val = value;

		if (*val != NULL)
			str_append(str, *val);
		break;
	}
	default:
		return FALSE;
	}
	return TRUE;
}

static void
settings_export(struct config_export_context *ctx,
		const struct config_module_parser *module_parser)
{
	const struct setting_parser_info *info = module_parser->info;
	uint8_t change_value;
	unsigned int i, count, define_idx;
	bool dump, dump_default = FALSE;

	for (define_idx = 0; info->defines[define_idx].key != NULL; define_idx++) {
		const struct setting_define *def = &info->defines[define_idx];

		change_value = module_parser->change_counters[define_idx];
		switch (ctx->scope) {
		case CONFIG_DUMP_SCOPE_DEFAULT:
			i_unreached();
		case CONFIG_DUMP_SCOPE_ALL_WITH_HIDDEN:
			dump_default = TRUE;
			break;
		case CONFIG_DUMP_SCOPE_ALL_WITHOUT_HIDDEN:
			if ((def->flags & SET_FLAG_HIDDEN) == 0) {
				/* not hidden - dump it */
				dump_default = TRUE;
				break;
			}
			/* hidden - dump default only if it's explicitly set */
			/* fall through */
		case CONFIG_DUMP_SCOPE_SET:
			if (change_value < CONFIG_PARSER_CHANGE_EXPLICIT) {
				/* setting is unchanged in config file */
				continue;
			}
			dump_default = TRUE;
			break;
		case CONFIG_DUMP_SCOPE_SET_AND_DEFAULT_OVERRIDES:
			if (change_value == 0) {
				/* setting is completely unchanged */
				continue;
			}
			dump_default = TRUE;
			break;
		case CONFIG_DUMP_SCOPE_CHANGED:
			if (change_value < CONFIG_PARSER_CHANGE_EXPLICIT) {
				/* setting is unchanged in config file */
				continue;
			}
			dump_default = FALSE;
			break;
		}

		bool value_stop_list = FALSE;
		dump = FALSE;
		str_truncate(ctx->value, 0);
		switch (def->type) {
		case SET_FILE:
		case SET_BOOL:
		case SET_SIZE:
		case SET_UINTMAX:
		case SET_UINT:
		case SET_UINT_OCT:
		case SET_TIME:
		case SET_TIME_MSECS:
		case SET_IN_PORT:
		case SET_STR:
		case SET_STR_NOVARS:
		case SET_ENUM: {
			string_t *default_str = NULL;
			bool default_changed = FALSE;
			const char *old_default;
			i_assert(info->defaults != NULL);
			if (module_parser->change_counters[define_idx] <= CONFIG_PARSER_CHANGE_DEFAULTS) {
				/* Setting isn't explicitly set. We need to see
				   if its default has changed. */
				const char *key_with_path = def->key;
				if (ctx->path_prefix[0] != '\0') {
					key_with_path = t_strconcat(
						ctx->path_prefix, def->key, NULL);
				}
				if (old_settings_default(ctx->dovecot_config_version,
							 def->key, key_with_path,
							 &old_default)) {
					default_str = t_str_new(strlen(old_default));
					str_append(default_str, old_default);
					default_changed = TRUE;
				}
			}

			if ((!dump_default || module_parser->change_counters[define_idx] == 0) &&
			    default_str == NULL) {
				const void *default_value =
					CONST_PTR_OFFSET(info->defaults,
							 def->offset);
				default_str = t_str_new(64);
				if (!config_export_type(default_str, default_value,
							def->type))
					i_unreached();
				if (def->type == SET_ENUM) {
					/* enum begins with default: followed
					   by other valid values */
					const char *p = strchr(str_c(default_str), ':');
					if (p != NULL) {
						str_truncate(default_str,
							p - str_c(default_str));
					}
				}
			}
			if (!dump_default &&
			    strcmp(str_c(default_str),
				   module_parser->settings[define_idx].str) == 0) {
				/* Explicitly set setting value wasn't
				   actually changed from its default. */
				break;
			}
			if (module_parser->change_counters[define_idx] >
					CONFIG_PARSER_CHANGE_DEFAULTS) {
				/* explicitly set */
				str_append(ctx->value,
					module_parser->settings[define_idx].str);
			} else if (module_parser->change_counters[define_idx] ==
				   CONFIG_PARSER_CHANGE_DEFAULTS && !default_changed) {
				/* default not changed by old version checks */
				str_append(ctx->value,
					module_parser->settings[define_idx].str);
			} else {
				str_append_str(ctx->value, default_str);
			}
			dump = TRUE;
			break;
		}
		case SET_STRLIST:
		case SET_BOOLLIST: {
			const ARRAY_TYPE(const_string) *val =
				module_parser->settings[define_idx].array.values;
			const char *const *strings;

			value_stop_list = module_parser->settings[define_idx].array.stop_list;
			if (hash_table_is_created(ctx->keys) &&
			    hash_table_lookup(ctx->keys, def->key) != NULL) {
				/* already added all of these */
				break;
			}
			if ((ctx->flags & CONFIG_DUMP_FLAG_DEDUPLICATE_KEYS) != 0)
				hash_table_insert(ctx->keys, def->key, def->key);

			if (val != NULL) {
				strings = array_get(val, &count);
				i_assert(count % 2 == 0);
			} else {
				strings = NULL;
				count = 0;
			}

			/* for doveconf -n to see this KEY_LIST */
			struct config_export_setting export_set = {
				.type = CONFIG_KEY_LIST,
				.def_type = def->type,
				.key = def->key,
				.key_define_idx = define_idx,
				.value = "",
				.list_count = count / 2,
				.value_stop_list = value_stop_list,
			};
			ctx->callback(&export_set, ctx->context);

			export_set.type = def->type == SET_STRLIST ?
				CONFIG_KEY_NORMAL : CONFIG_KEY_BOOLLIST_ELEM;
			for (i = 0; i < count; i += 2) T_BEGIN {
				export_set.key = t_strdup_printf("%s%c%s",
						      def->key,
						      SETTINGS_SEPARATOR,
						      strings[i]);
				export_set.list_idx = i / 2;
				export_set.value = strings[i+1];
				/* only the last element stops the list */
				export_set.value_stop_list = value_stop_list &&
					i + 2 == count;
				if (def->type == SET_BOOLLIST &&
				    strcmp(export_set.value, "no") == 0 &&
				    value_stop_list)
					; /* ignore */
				else
					ctx->callback(&export_set, ctx->context);
			} T_END;
			break;
		}
		case SET_FILTER_ARRAY: {
			const ARRAY_TYPE(const_string) *val =
				module_parser->settings[define_idx].array.values;
			const char *name;

			if (val == NULL)
				break;

			array_foreach_elem(val, name) {
				if (str_len(ctx->value) > 0)
					str_append_c(ctx->value, ' ');
				str_append(ctx->value,
					   settings_section_escape(name));
			}
			break;
		}
		case SET_FILTER_NAME:
		case SET_ALIAS:
			break;
		}
		if (str_len(ctx->value) > 0 || dump) {
			if (!hash_table_is_created(ctx->keys) ||
			    hash_table_lookup(ctx->keys, def->key) == NULL) {
				enum config_key_type type;

				if (def->type == SET_FILTER_ARRAY)
					type = CONFIG_KEY_FILTER_ARRAY;
				else
					type = CONFIG_KEY_NORMAL;
				struct config_export_setting export_set = {
					.type = type,
					.def_type = def->type,
					.key = def->key,
					.key_define_idx = define_idx,
					.value = str_c(ctx->value),
				};
				ctx->callback(&export_set, ctx->context);
				if ((ctx->flags & CONFIG_DUMP_FLAG_DEDUPLICATE_KEYS) != 0)
					hash_table_insert(ctx->keys, def->key, def->key);
			}
		}
	}
}

#undef config_export_init
struct config_export_context *
config_export_init(enum config_dump_scope scope,
		   enum config_dump_flags flags,
		   const char *dovecot_config_version, const char *path_prefix,
		   config_request_callback_t *callback, void *context)
{
	struct config_export_context *ctx;
	pool_t pool;

	pool = pool_alloconly_create(MEMPOOL_GROWING"config export", 512);
	ctx = p_new(pool, struct config_export_context, 1);
	ctx->pool = pool;

	ctx->flags = flags;
	ctx->callback = callback;
	ctx->context = context;
	ctx->scope = scope;
	ctx->dovecot_config_version = p_strdup(pool, dovecot_config_version);
	ctx->path_prefix = p_strdup(pool, path_prefix);
	ctx->value = str_new(pool, 256);
	if ((ctx->flags & CONFIG_DUMP_FLAG_DEDUPLICATE_KEYS) != 0)
		hash_table_create(&ctx->keys, ctx->pool, 0, str_hash, strcmp);
	return ctx;
}

void config_export_set_module_parsers(struct config_export_context *ctx,
				      const struct config_module_parser *module_parsers)
{
	ctx->module_parsers = module_parsers;
}

unsigned int config_export_get_parser_count(struct config_export_context *ctx)
{
	unsigned int i = 0;
	for (i = 0; ctx->module_parsers[i].info != NULL; i++) ;
	return i;
}

void config_export_free(struct config_export_context **_ctx)
{
	struct config_export_context *ctx = *_ctx;

	*_ctx = NULL;

	if (hash_table_is_created(ctx->keys))
		hash_table_destroy(&ctx->keys);
	pool_unref(&ctx->pool);
}

int config_export_all_parsers(struct config_export_context **_ctx)
{
	struct config_export_context *ctx = *_ctx;
	const char *error;
	unsigned int i;
	int ret = 0;

	*_ctx = NULL;

	for (i = 0; ctx->module_parsers[i].info != NULL; i++) {
		if (config_export_parser(ctx, i, &error) < 0) {
			i_error("%s", error);
			ret = -1;
			break;
		}
	}
	config_export_free(&ctx);
	return ret;
}

const struct setting_parser_info *
config_export_parser_get_info(struct config_export_context *ctx,
			      unsigned int parser_idx)
{
	return ctx->module_parsers[parser_idx].info;
}

int config_export_parser(struct config_export_context *ctx,
			 unsigned int parser_idx, const char **error_r)
{
	const struct config_module_parser *module_parser =
		&ctx->module_parsers[parser_idx];

	if (module_parser->delayed_error != NULL) {
		*error_r = module_parser->delayed_error;
		return -1;
	}
	if (module_parser->settings != NULL) T_BEGIN {
		settings_export(ctx, module_parser);
	} T_END;
	return 0;
}
