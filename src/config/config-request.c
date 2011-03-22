/* Copyright (c) 2005-2011 Dovecot authors, see the included COPYING file */

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

struct config_export_context {
	pool_t pool;
	string_t *value;
	string_t *prefix;
	struct hash_table *keys;
	enum config_dump_scope scope;

	config_request_callback_t *callback;
	void *context;

	const char *module;
	enum config_dump_flags flags;
	const struct config_module_parser *parsers;
	struct config_module_parser *dup_parsers;
	struct master_service_settings_output output;

	bool failed;
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
	str_printfa(str, "%llu %c", (unsigned long long)size, suffix);
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
	case SET_TIME: {
		const unsigned int *val = value, *dval = default_value;

		if (dump_default || dval == NULL || *val != *dval) {
			switch (type) {
			case SET_UINT_OCT:
				str_printfa(str, "0%o", *val);
				break;
			case SET_TIME:
				config_export_time(str, *val);
				break;
			default:
				str_printfa(str, "%u", *val);
				break;
			}
		}
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
		unsigned int len = strlen(*val);

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
setting_export_section_name(string_t *str, const struct setting_define *def,
			    const void *set, unsigned int idx)
{
	const char *const *name;
	size_t name_offset;

	if (def->type != SET_DEFLIST_UNIQUE) {
		/* not unique, use the index */
		str_printfa(str, "%u", idx);
		return;
	}
	name_offset = def->list_info->type_offset;
	i_assert(name_offset != (size_t)-1);

	name = CONST_PTR_OFFSET(set, name_offset);
	if (*name == NULL || **name == '\0') {
		/* no name, this one isn't unique. use the index. */
		str_printfa(str, "%u", idx);
	} else {
		str_append(str, settings_section_escape(*name));
	}
}

static void
settings_export(struct config_export_context *ctx,
		const struct setting_parser_info *info,
		bool parent_unique_deflist,
		const void *set, const void *change_set)
{
	const struct setting_define *def;
	const void *value, *default_value, *change_value;
	void *const *children = NULL, *const *change_children = NULL;
	unsigned int i, count, count2, prefix_len;
	const char *str;
	char *key;
	bool dump, dump_default = FALSE;

	for (def = info->defines; def->key != NULL; def++) {
		value = CONST_PTR_OFFSET(set, def->offset);
		default_value = info->defaults == NULL ? NULL :
			CONST_PTR_OFFSET(info->defaults, def->offset);
		change_value = CONST_PTR_OFFSET(change_set, def->offset);
		switch (ctx->scope) {
		case CONFIG_DUMP_SCOPE_ALL:
			dump_default = TRUE;
			break;
		case CONFIG_DUMP_SCOPE_SET:
			dump_default = *((const char *)change_value) != 0;
			break;
		case CONFIG_DUMP_SCOPE_CHANGED:
			dump_default = FALSE;
			break;
		}
		if (!parent_unique_deflist ||
		    (ctx->flags & CONFIG_DUMP_FLAG_HIDE_LIST_DEFAULTS) == 0) {
			/* .. */
		} else if (*((const char *)change_value) == 0 &&
			   def->offset != info->type_offset) {
			/* this is mainly for service {} blocks. if value
			   hasn't changed, it's the default. even if
			   info->defaults has a different value. */
			default_value = value;
		} else {
			/* value is set explicitly, but we don't know the
			   default here. assume it's not the default. */
			dump_default = TRUE;
		}

		dump = FALSE;
		count = 0;
		str_truncate(ctx->value, 0);
		switch (def->type) {
		case SET_BOOL:
		case SET_SIZE:
		case SET_UINT:
		case SET_UINT_OCT:
		case SET_TIME:
		case SET_STR_VARS:
		case SET_STR:
		case SET_ENUM:
			if (!config_export_type(ctx->value, value,
						default_value, def->type,
						dump_default, &dump))
				i_unreached();
			break;
		case SET_DEFLIST:
		case SET_DEFLIST_UNIQUE: {
			const ARRAY_TYPE(void_array) *val = value;
			const ARRAY_TYPE(void_array) *change_val = change_value;

			if (!array_is_created(val))
				break;

			children = array_get(val, &count);
			for (i = 0; i < count; i++) {
				if (i > 0)
					str_append_c(ctx->value, ' ');
				setting_export_section_name(ctx->value, def, children[i], i);
			}
			change_children = array_get(change_val, &count2);
			i_assert(count == count2);
			break;
		}
		case SET_STRLIST: {
			const ARRAY_TYPE(const_string) *val = value;
			const char *const *strings;

			if (!array_is_created(val))
				break;

			key = p_strconcat(ctx->pool, str_c(ctx->prefix),
					  def->key, NULL);

			if (hash_table_lookup(ctx->keys, key) != NULL) {
				/* already added all of these */
				break;
			}
			hash_table_insert(ctx->keys, key, key);
			/* for doveconf -n to see this KEY_LIST */
			ctx->callback(key, "", CONFIG_KEY_LIST, ctx->context);

			strings = array_get(val, &count);
			i_assert(count % 2 == 0);
			for (i = 0; i < count; i += 2) {
				str = p_strdup_printf(ctx->pool, "%s%s%c%s",
						      str_c(ctx->prefix),
						      def->key,
						      SETTINGS_SEPARATOR,
						      strings[i]);
				ctx->callback(str, strings[i+1],
					      CONFIG_KEY_NORMAL, ctx->context);
			}
			count = 0;
			break;
		}
		case SET_ALIAS:
			break;
		}
		if (str_len(ctx->value) > 0 || dump) {
			key = p_strconcat(ctx->pool, str_c(ctx->prefix),
					  def->key, NULL);
			if (hash_table_lookup(ctx->keys, key) == NULL) {
				enum config_key_type type;

				if (def->offset == info->type_offset &&
				    parent_unique_deflist)
					type = CONFIG_KEY_UNIQUE_KEY;
				else if (SETTING_TYPE_IS_DEFLIST(def->type))
					type = CONFIG_KEY_LIST;
				else
					type = CONFIG_KEY_NORMAL;
				ctx->callback(key, str_c(ctx->value), type,
					ctx->context);
				hash_table_insert(ctx->keys, key, key);
			}
		}

		prefix_len = str_len(ctx->prefix);
		for (i = 0; i < count; i++) {
			str_append(ctx->prefix, def->key);
			str_append_c(ctx->prefix, SETTINGS_SEPARATOR);
			setting_export_section_name(ctx->prefix, def, children[i], i);
			str_append_c(ctx->prefix, SETTINGS_SEPARATOR);
			settings_export(ctx, def->list_info,
					def->type == SET_DEFLIST_UNIQUE,
					children[i], change_children[i]);

			str_truncate(ctx->prefix, prefix_len);
		}
	}
}

struct config_export_context *
config_export_init(const char *module, enum config_dump_scope scope,
		   enum config_dump_flags flags,
		   config_request_callback_t *callback, void *context)
{
	struct config_export_context *ctx;
	pool_t pool;

	i_assert(module != NULL);

	pool = pool_alloconly_create("config export", 1024*64);
	ctx = p_new(pool, struct config_export_context, 1);
	ctx->pool = pool;

	ctx->module = p_strdup(pool, module);
	ctx->flags = flags;
	ctx->callback = callback;
	ctx->context = context;
	ctx->scope = scope;
	ctx->value = t_str_new(256);
	ctx->prefix = t_str_new(64);
	ctx->keys = hash_table_create(default_pool, ctx->pool, 0,
				      str_hash, (hash_cmp_callback_t *)strcmp);
	return ctx;
}

void config_export_by_filter(struct config_export_context *ctx,
			     const struct config_filter *filter)
{
	const char *error;

	if (config_filter_parsers_get(config_filter, ctx->pool,
				      ctx->module, filter,
				      &ctx->dup_parsers, &ctx->output,
				      &error) < 0) {
		i_error("%s", error);
		ctx->failed = TRUE;
	}
	ctx->parsers = ctx->dup_parsers;
}

void config_export_parsers(struct config_export_context *ctx,
			   const struct config_module_parser *parsers)
{
	ctx->parsers = parsers;
}

void config_export_get_output(struct config_export_context *ctx,
			      struct master_service_settings_output *output_r)
{
	*output_r = ctx->output;
}

static void config_export_free(struct config_export_context *ctx)
{
	if (ctx->dup_parsers != NULL)
		config_filter_parsers_free(ctx->dup_parsers);
	hash_table_destroy(&ctx->keys);
	pool_unref(&ctx->pool);
}

int config_export_finish(struct config_export_context **_ctx)
{
	struct config_export_context *ctx = *_ctx;
	const struct config_module_parser *parser;
	const char *error;
	unsigned int i;
	int ret = 0;

	*_ctx = NULL;

	if (ctx->failed) {
		config_export_free(ctx);
		return -1;
	}

	for (i = 0; ctx->parsers[i].root != NULL; i++) {
		parser = &ctx->parsers[i];
		if (*ctx->module != '\0' &&
		    !config_module_want_parser(config_module_parsers,
					       ctx->module, parser->root))
			continue;

		settings_export(ctx, parser->root, FALSE,
				settings_parser_get(parser->parser),
				settings_parser_get_changes(parser->parser));

		if ((ctx->flags & CONFIG_DUMP_FLAG_CHECK_SETTINGS) != 0) {
			settings_parse_var_skip(parser->parser);
			if (!settings_parser_check(parser->parser, ctx->pool,
						   &error)) {
				if ((ctx->flags & CONFIG_DUMP_FLAG_CALLBACK_ERRORS) != 0) {
					ctx->callback(NULL, error, CONFIG_KEY_ERROR,
						      ctx->context);
				} else {
					i_error("%s", error);
					ret = -1;
					break;
				}
			}
		}
	}
	config_export_free(ctx);
	return ret;
}
