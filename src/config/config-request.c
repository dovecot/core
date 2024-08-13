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
	if ((stamp_msecs % 1000) == 0)
		config_export_time(str, stamp_msecs/1000);
	else
		str_printfa(str, "%u ms", stamp_msecs);
}

bool config_export_type(string_t *str, const void *value,
			const void *default_value,
			enum setting_type type, bool dump_default,
			bool *dump_r)
{
	switch (type) {
	case SET_BOOL: {
		const bool *val = value, *dval = default_value;

		if (dump_default || dval == NULL || *val != *dval)
			str_append(str, *val ? "yes" : "no");
		break;
	}
	case SET_SIZE: {
		const uoff_t *val = value, *dval = default_value;

		if (dump_default || dval == NULL || *val != *dval)
			config_export_size(str, *val);
		break;
	}
	case SET_UINT:
	case SET_UINT_OCT:
	case SET_TIME:
	case SET_TIME_MSECS: {
		const unsigned int *val = value, *dval = default_value;

		if (dump_default || dval == NULL || *val != *dval) {
			switch (type) {
			case SET_UINT_OCT:
				str_printfa(str, "0%o", *val);
				break;
			case SET_TIME:
				config_export_time(str, *val);
				break;
			case SET_TIME_MSECS:
				config_export_time_msecs(str, *val);
				break;
			default:
				str_printfa(str, "%u", *val);
				break;
			}
		}
		break;
	}
	case SET_IN_PORT: {
		const in_port_t *val = value, *dval = default_value;

		if (dump_default || dval == NULL || *val != *dval)
			str_printfa(str, "%u", *val);
		break;
	}
	case SET_STR_VARS: {
		const char *const *val = value, *sval;
		const char *const *_dval = default_value;
		const char *dval = _dval == NULL ? NULL : *_dval;

		i_assert(*val == NULL ||
			 **val == SETTING_STRVAR_UNEXPANDED[0]);

		sval = *val == NULL ? NULL : (*val + 1);
		if ((dump_default || null_strcmp(sval, dval) != 0) &&
		    sval != NULL) {
			str_append(str, sval);
			*dump_r = TRUE;
		}
		break;
	}
	case SET_STR: {
		const char *const *val = value;
		const char *const *_dval = default_value;
		const char *dval = _dval == NULL ? NULL : *_dval;

		if ((dump_default || null_strcmp(*val, dval) != 0) &&
		    *val != NULL) {
			str_append(str, *val);
			*dump_r = TRUE;
		}
		break;
	}
	case SET_ENUM: {
		const char *const *val = value;
		size_t len = strlen(*val);

		if (dump_default)
			str_append(str, *val);
		else {
			const char *const *_dval = default_value;
			const char *dval = _dval == NULL ? NULL : *_dval;

			i_assert(dval != NULL);
			if (strncmp(*val, dval, len) != 0 ||
			    ((*val)[len] != ':' && (*val)[len] != '\0'))
				str_append(str, *val);
		}
		break;
	}
	default:
		return FALSE;
	}
	return TRUE;
}

static void
settings_export(struct config_export_context *ctx,
		const struct setting_parser_info *info,
		const void *set, const void *change_set)
{
	const void *value, *default_value, *change_value;
	unsigned int i, count, define_idx;
	const char *str;
	bool dump, dump_default = FALSE;

	for (define_idx = 0; info->defines[define_idx].key != NULL; define_idx++) {
		const struct setting_define *def = &info->defines[define_idx];

		value = CONST_PTR_OFFSET(set, def->offset);
		default_value = info->defaults == NULL ? NULL :
			CONST_PTR_OFFSET(info->defaults, def->offset);
		change_value = CONST_PTR_OFFSET(change_set, def->offset);
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
			if (*((const uint8_t *)change_value) < CONFIG_PARSER_CHANGE_EXPLICIT) {
				/* setting is unchanged in config file */
				continue;
			}
			dump_default = TRUE;
			break;
		case CONFIG_DUMP_SCOPE_SET_AND_DEFAULT_OVERRIDES:
			if (*((const uint8_t *)change_value) < CONFIG_PARSER_CHANGE_INTERNAL) {
				/* setting is completely unchanged */
				continue;
			}
			dump_default = TRUE;
			break;
		case CONFIG_DUMP_SCOPE_CHANGED:
			if (*((const uint8_t *)change_value) < CONFIG_PARSER_CHANGE_EXPLICIT) {
				/* setting is unchanged in config file */
				continue;
			}
			dump_default = FALSE;
			break;
		}

		dump = FALSE;
		str_truncate(ctx->value, 0);
		switch (def->type) {
		case SET_BOOL:
		case SET_SIZE:
		case SET_UINT:
		case SET_UINT_OCT:
		case SET_TIME:
		case SET_TIME_MSECS:
		case SET_IN_PORT:
		case SET_STR_VARS:
		case SET_STR:
		case SET_ENUM:
			if (!config_export_type(ctx->value, value,
						default_value, def->type,
						dump_default, &dump))
				i_unreached();
			break;
		case SET_STRLIST: {
			const ARRAY_TYPE(const_string) *val = value;
			const char *const *strings;

			if (!array_is_created(val))
				break;

			if (hash_table_is_created(ctx->keys) &&
			    hash_table_lookup(ctx->keys, def->key) != NULL) {
				/* already added all of these */
				break;
			}
			if ((ctx->flags & CONFIG_DUMP_FLAG_DEDUPLICATE_KEYS) != 0)
				hash_table_insert(ctx->keys, def->key, def->key);

			/* for doveconf -n to see this KEY_LIST */
			struct config_export_setting export_set = {
				.type = CONFIG_KEY_LIST,
				.key = def->key,
				.key_define_idx = define_idx,
				.value = "",
			};
			ctx->callback(&export_set, ctx->context);

			strings = array_get(val, &count);
			i_assert(count % 2 == 0);
			for (i = 0; i < count; i += 2) T_BEGIN {
				str = t_strdup_printf("%s%c%s",
						      def->key,
						      SETTINGS_SEPARATOR,
						      strings[i]);
				struct config_export_setting export_set = {
					.type = CONFIG_KEY_NORMAL,
					.key = str,
					.key_define_idx = define_idx,
					.value = strings[i+1],
				};
				ctx->callback(&export_set, ctx->context);
			} T_END;
			break;
		}
		case SET_FILTER_ARRAY: {
			const ARRAY_TYPE(const_string) *val = value;
			const char *name;

			if (!array_is_created(val))
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

const char *
config_export_get_import_environment(struct config_export_context *ctx)
{
	return config_module_parsers_get_setting(ctx->module_parsers,
		"master_service", "import_environment");
}

const char *config_export_get_base_dir(struct config_export_context *ctx)
{
	return config_module_parsers_get_setting(ctx->module_parsers,
						 "master_service", "base_dir");
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
	if (module_parser->parser != NULL) T_BEGIN {
		void *set = settings_parser_get_set(module_parser->parser);
		settings_export(ctx, module_parser->info, set,
				settings_parser_get_changes(module_parser->parser));
	} T_END;
	return 0;
}
