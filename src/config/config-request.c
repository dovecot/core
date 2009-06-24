/* Copyright (C) 2005-2009 Dovecot authors, see the included COPYING file */

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

struct settings_export_context {
	pool_t pool;
	string_t *value;
	string_t *prefix;
	struct hash_table *keys;
	bool export_defaults;

	config_request_callback_t *callback;
	void *context;
};

static bool parsers_are_connected(struct setting_parser_info *root,
				  struct setting_parser_info *info)
{
	struct setting_parser_info *const *dep, *p;

	/* we're trying to find info or its parents from root's dependencies. */

	for (p = info; p != NULL; p = p->parent) {
		if (p == root)
			return TRUE;
	}

	if (root->dependencies != NULL) {
		for (dep = root->dependencies; *dep != NULL; dep++) {
			for (p = info; p != NULL; p = p->parent) {
				if (p == *dep)
					return TRUE;
			}
		}
	}
	return FALSE;
}

static bool
config_setting_parser_is_in_service(const struct config_setting_parser_list *list,
				    const char *module)
{
	struct config_setting_parser_list *l;

	if (strcmp(list->module_name, module) == 0)
		return TRUE;
	if (list->root == &master_service_setting_parser_info) {
		/* everyone wants master service settings */
		return TRUE;
	}

	for (l = config_setting_parsers; l->module_name != NULL; l++) {
		if (strcmp(l->module_name, module) != 0)
			continue;

		/* see if we can find a way to get from the original parser
		   to this parser */
		if (parsers_are_connected(l->root, list->root))
			return TRUE;
	}
	return FALSE;
}

static void settings_export(struct settings_export_context *ctx,
			    const struct setting_parser_info *info,
			    const void *set)
{
	const struct setting_define *def;
	const void *value, *default_value;
	void *const *children = NULL;
	unsigned int i, count, prefix_len;
	const char *str;
	char *key;
	bool dump;

	for (def = info->defines; def->key != NULL; def++) {
		value = CONST_PTR_OFFSET(set, def->offset);
		default_value = info->defaults == NULL ? NULL :
			CONST_PTR_OFFSET(info->defaults, def->offset);

		dump = FALSE;
		count = 0;
		str_truncate(ctx->value, 0);
		switch (def->type) {
		case SET_BOOL: {
			const bool *val = value, *dval = default_value;
			if (ctx->export_defaults ||
			    dval == NULL || *val != *dval) {
				str_append(ctx->value,
					   *val ? "yes" : "no");
			}
			break;
		}
		case SET_UINT: {
			const unsigned int *val = value, *dval = default_value;
			if (ctx->export_defaults ||
			    dval == NULL || *val != *dval)
				str_printfa(ctx->value, "%u", *val);
			break;
		}
		case SET_STR_VARS: {
			const char *const *val = value, *sval;
			const char *const *_dval = default_value;
			const char *dval = _dval == NULL ? NULL : *_dval;

			i_assert(*val == NULL ||
				 **val == SETTING_STRVAR_UNEXPANDED[0]);

			sval = *val == NULL ? NULL : (*val + 1);
			if ((ctx->export_defaults ||
			     null_strcmp(sval, dval) != 0) && sval != NULL) {
				str_append(ctx->value, sval);
				dump = TRUE;
			}
			break;
		}
		case SET_STR: {
			const char *const *val = value;
			const char *const *_dval = default_value;
			const char *dval = _dval == NULL ? NULL : *_dval;

			if ((ctx->export_defaults ||
			     null_strcmp(*val, dval) != 0) && *val != NULL) {
				str_append(ctx->value, *val);
				dump = TRUE;
			}
			break;
		}
		case SET_ENUM: {
			const char *const *val = value;
			const char *const *_dval = default_value;
			const char *dval = _dval == NULL ? NULL : *_dval;
			unsigned int len = strlen(*val);

			if (ctx->export_defaults ||
			    strncmp(*val, dval, len) != 0 ||
			    ((*val)[len] != ':' && (*val)[len] != '\0'))
				str_append(ctx->value, *val);
			break;
		}
		case SET_DEFLIST: {
			const ARRAY_TYPE(void_array) *val = value;

			if (!array_is_created(val))
				break;

			children = array_get(val, &count);
			for (i = 0; i < count; i++) {
				if (i > 0)
					str_append_c(ctx->value, ' ');
				str_printfa(ctx->value, "%u", i);
			}
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
			ctx->callback(key, "0", TRUE, ctx->context);

			strings = array_get(val, &count);
			i_assert(count % 2 == 0);
			for (i = 0; i < count; i += 2) {
				str = p_strdup_printf(ctx->pool, "%s%s%c0%c%s",
						      str_c(ctx->prefix),
						      def->key,
						      SETTINGS_SEPARATOR,
						      SETTINGS_SEPARATOR,
						      strings[i]);
				ctx->callback(str, strings[i+1], FALSE,
					      ctx->context);
			}
			count = 0;
			break;
		}
		}
		if (str_len(ctx->value) > 0 || dump) {
			key = p_strconcat(ctx->pool, str_c(ctx->prefix),
					  def->key, NULL);
			if (hash_table_lookup(ctx->keys, key) == NULL) {
				ctx->callback(key, str_c(ctx->value),
					      def->type == SET_DEFLIST,
					      ctx->context);
				hash_table_insert(ctx->keys, key, key);
			}
		}

		prefix_len = str_len(ctx->prefix);
		for (i = 0; i < count; i++) {
			str_append(ctx->prefix, def->key);
			str_append_c(ctx->prefix, SETTINGS_SEPARATOR);
			str_printfa(ctx->prefix, "%u", i);
			str_append_c(ctx->prefix, SETTINGS_SEPARATOR);
			settings_export(ctx, def->list_info, children[i]);

			str_truncate(ctx->prefix, prefix_len);
		}
	}
}

void config_request_handle(const struct config_filter *filter,
			   const char *module, enum config_dump_flags flags,
			   config_request_callback_t *callback, void *context)
{
	const struct config_setting_parser_list *l;
	struct settings_export_context ctx;

	memset(&ctx, 0, sizeof(ctx));
	ctx.pool = pool_alloconly_create("config request", 10240);
	ctx.callback = callback;
	ctx.context = context;
	ctx.export_defaults = (flags & CONFIG_DUMP_FLAG_DEFAULTS) != 0;
	ctx.value = t_str_new(256);
	ctx.prefix = t_str_new(64);
	ctx.keys = hash_table_create(default_pool, ctx.pool, 0,
				     str_hash, (hash_cmp_callback_t *)strcmp);

	l = config_filter_match_parsers(config_filter, filter);
	for (; l->module_name != NULL; l++) {
		if (*module == '\0' ||
		    config_setting_parser_is_in_service(l, module)) {
			settings_export(&ctx, l->root,
					settings_parser_get(l->parser));
		}
	}
	hash_table_destroy(&ctx.keys);
	pool_unref(&ctx.pool);
}
