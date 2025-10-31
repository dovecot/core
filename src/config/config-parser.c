/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "bsearch-insert-pos.h"
#include "str.h"
#include "hash.h"
#include "llist.h"
#include "strescape.h"
#include "istream.h"
#include "module-dir.h"
#include "version.h"
#include "settings.h"
#include "service-settings.h"
#include "master-service-settings.h"
#include "all-settings.h"
#include "old-set-parser.h"
#include "config-request.h"
#include "config-dump-full.h"
#include "config-parser-private.h"
#include "strfuncs.h"

#include "default-settings-import.h"

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <ctype.h>
#ifdef HAVE_GLOB_H
#  include <glob.h>
#endif

#ifndef GLOB_BRACE
#  define GLOB_BRACE 0
#endif

#define DNS_LOOKUP_TIMEOUT_SECS 30
#define DNS_LOOKUP_WARN_SECS 5

struct config_include_group_filters {
	const char *label;
	ARRAY(struct config_filter_parser *) filters;
};

struct config_parsed {
	pool_t pool;
	const char *dovecot_config_version;
	struct config_filter_parser *const *filter_parsers;
	struct config_module_parser *module_parsers;
	ARRAY_TYPE(config_path) seen_paths;
	ARRAY_TYPE(const_string) errors;
	HASH_TABLE_TYPE(include_group) include_groups;
	HASH_TABLE_TYPE(config_key) all_keys;
};

ARRAY_DEFINE_TYPE(setting_parser_info_p, const struct setting_parser_info *);

static const enum settings_parser_flags settings_parser_flags =
	SETTINGS_PARSER_FLAG_IGNORE_UNKNOWN_KEYS;

struct module *modules;
void (*hook_config_parser_begin)(struct config_parser_context *ctx);
int (*hook_config_parser_end)(struct config_parser_context *ctx,
			      struct config_parsed *new_config,
			      struct event *event, const char **error_r);

static ARRAY_TYPE(config_service) services_free_at_deinit = ARRAY_INIT;
static ARRAY_TYPE(setting_parser_info_p) infos_free_at_deinit = ARRAY_INIT;
static string_t *config_import;

static struct config_filter_parser *
config_filter_parser_find(struct config_parser_context *ctx,
			  const struct config_filter *filter);
static struct config_section_stack *
config_add_new_section(struct config_parser_context *ctx);
static struct config_filter_parser *
config_add_new_parser(struct config_parser_context *ctx,
		      const struct config_filter *filter,
		      struct config_filter_parser *parent_filter_parser);
static int config_write_keyvariable(struct config_parser_context *ctx,
				    struct config_filter_parser *filter_parser,
				    const char *key, const char *value,
				    string_t *prefixed_str,
				    bool delay_set_expand);
static int
config_apply_exact_line(struct config_parser_context *ctx,
			const struct config_line *line,
			const char *key, const char *prefixed_value);
static int
config_apply_line_full(struct config_parser_context *ctx,
		       const struct config_line *line,
		       const char *key_with_path,
		       const char *prefixed_value, const char **full_key_r,
		       bool autoprefix, bool *root_setting_r);

static void
config_module_parser_init(struct config_parser_context *ctx,
			  struct config_module_parser *module_parser)
{
	module_parser->set_count =
		setting_parser_info_get_define_count(module_parser->info);
	module_parser->settings = module_parser->set_count == 0 ? NULL :
		p_new(ctx->pool, union config_module_parser_setting,
		      module_parser->set_count);
	module_parser->change_counters = module_parser->set_count == 0 ? NULL :
		p_new(ctx->pool, uint8_t, module_parser->set_count);
}

void config_parser_set_change_counter(struct config_parser_context *ctx,
				      uint8_t change_counter)
{
	ctx->change_counter = change_counter;
}

static void
config_parser_add_seen_file(struct config_parser_context *ctx,
			    const struct stat *st, const char *path)
{
	struct config_path *seen_path = array_append_space(&ctx->seen_paths);
	seen_path->path = p_strdup(ctx->pool, path);
	seen_path->st = *st;
}

static int
config_parser_add_seen_file_fd(struct config_parser_context *ctx,
			       int fd, const char *path, const char **error_r)
{
	struct stat st;

	if (fstat(fd, &st) < 0) {
		*error_r = t_strdup_printf("fstat(%s) failed: %m", path);
		return -1;
	}
	config_parser_add_seen_file(ctx, &st, path);
	return 0;
}

static struct config_section_stack *
config_parser_add_filter_array(struct config_parser_context *ctx,
			       const char *filter_key, const char *name)
{
	const char *prefixed_name =
		t_strdup_printf("%c%s", CONFIG_VALUE_PREFIX_EXPANDED, name);
	config_parser_set_change_counter(ctx, CONFIG_PARSER_CHANGE_DEFAULTS);
	if (config_apply_exact_line(ctx, NULL, filter_key, prefixed_name) < 0) {
		i_panic("Failed to add %s %s: %s", filter_key, name,
			ctx->error);
	}
	config_parser_set_change_counter(ctx, CONFIG_PARSER_CHANGE_EXPLICIT);

	struct config_section_stack *section;
	section = config_add_new_section(ctx);
	struct config_filter filter = {
		.filter_name = p_strdup_printf(ctx->pool, "%s/%s",
					       filter_key, name),
		.filter_name_array = TRUE,
		.default_settings = TRUE,
	};
	section->is_filter = TRUE;
	section->filter_parser =
		config_add_new_parser(ctx, &filter, ctx->cur_section->filter_parser);
	section->filter_parser->filter_required_setting_seen = TRUE;
	return section;
}

static int
config_apply_default(struct config_parser_context *ctx,
		     const char *key_with_path, const char *value)
{
	/* This check is only for built-in defaults where this is good
	   enough, even if not perfect. */
	bool have_str_vars = strstr(value, "$SET:") != NULL;
	const char *prefixed_value =
		t_strdup_printf("%c%s", !have_str_vars ?
				CONFIG_VALUE_PREFIX_EXPANDED :
				CONFIG_VALUE_PREFIX_SET_UNEXPANDED, value);

	bool root_setting;
	return config_apply_line_full(ctx, NULL, key_with_path,
				      prefixed_value, NULL,
				      TRUE, &root_setting);
}

static void
config_parser_add_service_default_struct(struct config_parser_context *ctx,
					 unsigned int service_info_idx,
					 const struct service_settings *default_set)
{
#define SERVICE_SETTING_TYPE_HAS_DEFAULT(type) \
	((type) == SET_UINT || (type) == SET_SIZE || \
	 (type) == SET_TIME || (type) == SET_TIME_MSECS)
	const struct setting_parser_info *info = all_infos[service_info_idx];
	string_t *value_str = t_str_new(64);

	config_parser_set_change_counter(ctx, CONFIG_PARSER_CHANGE_DEFAULTS);
	for (unsigned int i = 0; info->defines[i].key != NULL; i++) {
		const void *value = CONST_PTR_OFFSET(default_set,
						     info->defines[i].offset);
		i_assert(value != NULL);

		str_truncate(value_str, 0);
		if (!config_export_type(value_str, value, info->defines[i].type))
			continue;
		if (strcmp(str_c(value_str), "0") == 0 &&
		    SERVICE_SETTING_TYPE_HAS_DEFAULT(info->defines[i].type)) {
			/* 0 uses the global default */
			continue;
		}

		if (config_apply_default(ctx, info->defines[i].key,
					 str_c(value_str)) < 0) {
			i_panic("Failed to add default setting %s=%s for service %s: %s",
				info->defines[i].key, str_c(value_str)  + 1,
				default_set->name, ctx->error);
		}
	}
	config_parser_set_change_counter(ctx, CONFIG_PARSER_CHANGE_EXPLICIT);
}

static void
config_parser_add_service_default_keyvalues(struct config_parser_context *ctx,
					    const char *service_name,
					    const struct setting_keyvalue *defaults)
{
	struct config_filter_parser *orig_filter_parser =
		ctx->cur_section->filter_parser;
	string_t *key_with_path = str_new(default_pool, 128);
	const char *p;

	str_printfa(key_with_path, "service/%s/", service_name);
	size_t key_prefix_len = str_len(key_with_path);

	for (unsigned int i = 0; defaults[i].key != NULL; i++) T_BEGIN {
		const char *key = defaults[i].key;

		if ((p = strchr(key, '/')) != NULL &&
		    (p = strchr(p + 1, '/')) != NULL) {
			/* *_listener filter */
			const char *escaped_key = t_strdup_until(key, p);
			struct config_filter filter = {
				.filter_name = settings_section_unescape(escaped_key),
				.filter_name_array = TRUE,
				.default_settings = TRUE,
				.parent = &orig_filter_parser->filter,
			};
			struct config_filter_parser *filter_parser =
				config_filter_parser_find(ctx, &filter);
			if (filter_parser == NULL) {
				filter.filter_name =
					p_strdup(ctx->pool, filter.filter_name);
				ctx->cur_section->filter_parser =
					config_add_new_parser(ctx, &filter, orig_filter_parser);
				ctx->cur_section->filter_parser->filter_required_setting_seen = TRUE;
			} else {
				ctx->cur_section->filter_parser = filter_parser;
			}
			key = p + 1;
		}

		const char *value = defaults[i].value;
		if (ctx->dovecot_config_version != NULL) {
			str_truncate(key_with_path, key_prefix_len);
			str_append(key_with_path, defaults[i].key);

			(void)old_settings_default(ctx->dovecot_config_version,
				defaults[i].key, str_c(key_with_path), &value);
		}

		config_parser_set_change_counter(ctx, CONFIG_PARSER_CHANGE_DEFAULTS);
		if (config_apply_default(ctx, key, value) < 0) {
			i_panic("Failed to add default setting %s=%s for service %s: %s",
				defaults[i].key, value,
				service_name, ctx->error);
		}
		config_parser_set_change_counter(ctx, CONFIG_PARSER_CHANGE_EXPLICIT);

		ctx->cur_section->filter_parser = orig_filter_parser;
	} T_END;
	str_free(&key_with_path);
}

static void config_parser_add_services(struct config_parser_context *ctx,
				       unsigned int service_info_idx)
{
	struct config_section_stack *orig_section = ctx->cur_section;

	for (unsigned int i = 0; config_all_services[i].set != NULL; i++) T_BEGIN {
		const struct service_settings *set = config_all_services[i].set;
		struct config_section_stack *section =
			config_parser_add_filter_array(ctx, "service",
						       set->name);
		ctx->cur_section = section;
		config_parser_add_service_default_struct(ctx, service_info_idx, set);

		const struct setting_keyvalue *defaults =
			config_all_services[i].defaults;
		if (defaults != NULL) {
			config_parser_add_service_default_keyvalues(
				ctx, set->name, defaults);
		}
		ctx->cur_section = orig_section;
	} T_END;
}

static void
config_parser_add_info_defaults_arr(struct config_parser_context *ctx,
				    const struct setting_parser_info *info,
				    const struct setting_keyvalue *defaults)
{
	if (defaults == NULL)
		return;

	for (unsigned int i = 0; defaults[i].key != NULL; i++) {
		const char *value = defaults[i].value;
		if (ctx->dovecot_config_version != NULL) {
			(void)old_settings_default(ctx->dovecot_config_version,
				defaults[i].key, defaults[i].key, &value);
		}
		if (config_apply_default(ctx, defaults[i].key, value) < 0) {
			i_panic("Failed to add default setting %s=%s for struct %s: %s",
				defaults[i].key, defaults[i].value,
				info->name, ctx->error);
		}
	}
}

static void config_parser_add_info_defaults(struct config_parser_context *ctx,
					    const struct setting_parser_info *info)
{
	config_parser_set_change_counter(ctx, CONFIG_PARSER_CHANGE_DEFAULTS);
	config_parser_add_info_defaults_arr(ctx, info, info->default_settings);
	config_parser_set_change_counter(ctx, CONFIG_PARSER_CHANGE_EXPLICIT);
}

static bool
config_parser_is_in_localremote(struct config_section_stack *section)
{
	const struct config_filter *filter = &section->filter_parser->filter;

	do {
		if (filter->local_name != NULL || filter->local_bits > 0 ||
		    filter->remote_bits > 0)
			return TRUE;
		filter = filter->parent;
	} while (filter != NULL);
	return FALSE;
}

static const char *
fix_relative_path(const char *path, struct input_stack *input)
{
	const char *p;

	if (*path == '/')
		return path;

	p = strrchr(input->path, '/');
	if (p == NULL)
		return path;

	return t_strconcat(t_strdup_until(input->path, p+1), path, NULL);
}

static int
config_apply_error(struct config_parser_context *ctx, const char *key)
{
	struct config_parser_key *config_key;

	if ((ctx->flags & CONFIG_PARSE_FLAG_DELAY_ERRORS) == 0)
		return -1;

	/* Couldn't get value for the setting, but we're delaying error
	   handling. Mark all settings parsers containing this key as failed.
	   See config-parser.h for details. */
	config_key = hash_table_lookup(ctx->all_keys, t_strcut(key, '/'));
	if (config_key == NULL)
		return -1;

	for (; config_key != NULL; config_key = config_key->next) {
		struct config_module_parser *l =
			&ctx->cur_section->filter_parser->module_parsers[config_key->info_idx];
		if (l->delayed_error == NULL)
			l->delayed_error = ctx->error;
		ctx->error = NULL;
	}
	return 0;
}

static struct config_filter_parser *
config_filters_find_child(struct config_filter_parser *parent,
			  const struct config_filter *wanted_filter)
{
	struct config_filter_parser *filter;

	for (filter = parent->children_head; filter != NULL; filter = filter->next) {
		if (config_filters_equal_no_recursion(&filter->filter, wanted_filter))
			return filter;
	}
	return NULL;
}

static void
config_filter_fill_reverse_default_siblings(struct config_filter_parser *p1_parent,
					    struct config_filter_parser *p2_parent)
{
	struct config_filter_parser *p1, *p2;

	p2_parent->reverse_default_sibling = p1_parent;
	p1_parent->reverse_default_sibling = p2_parent;

	for (p1 = p1_parent->children_head; p1 != NULL; p1 = p1->next) {
		p2 = config_filters_find_child(p2_parent, &p1->filter);
		if (p2 != NULL)
			config_filter_fill_reverse_default_siblings(p2, p1);
	}
}

static void
config_parse_fill_reverse_default_siblings(struct config_parser_context *ctx)
{
	struct config_filter_parser *root_parser, *defaults_parser;

	if (ctx->reverse_parsers_set)
		return;

	ctx->reverse_parsers_set = TRUE;
	root_parser = array_idx_elem(&ctx->all_filter_parsers, 0);
	defaults_parser = array_idx_elem(&ctx->all_filter_parsers, 1);
	i_assert(config_filter_is_empty_defaults(&defaults_parser->filter));

	config_filter_fill_reverse_default_siblings(root_parser, defaults_parser);
}

static int
config_filter_get_value(struct config_parser_context *ctx,
			struct config_filter_parser *filter_parser,
			const struct setting_define *def,
			struct config_parser_key *config_key,
			const char *key, string_t *str)
{
	struct config_module_parser *l =
		&filter_parser->module_parsers[config_key->info_idx];
	struct config_module_parser *l2 =
		filter_parser->reverse_default_sibling == NULL ? NULL :
		&filter_parser->reverse_default_sibling->module_parsers[config_key->info_idx];

	/* We have settings in two filter_parser trees: the built-in default
	   settings and non-default settings. When both tree nodes exist,
	   prefer the non-default settings. Otherwise use the first node in the
	   hierarchy where the setting has been changed. */
	if (l2 != NULL && filter_parser->filter.default_settings) {
		/* swap the parsers so non-defaults is checked first */
		i_assert(!filter_parser->reverse_default_sibling->filter.default_settings);
		struct config_module_parser *l_swap = l;
		l = l2;
		l2 = l_swap;
	}

	const union config_module_parser_setting *value = NULL;
	if (l->change_counters != NULL &&
	    l->change_counters[config_key->define_idx] != 0)
		value = &l->settings[config_key->define_idx];
	else if (l2 != NULL && l2->change_counters != NULL &&
		 l2->change_counters[config_key->define_idx] != 0)
		value = &l2->settings[config_key->define_idx];

	if (value != NULL) {
		if (value->prefixed_str[0] == CONFIG_VALUE_PREFIX_EXPANDED) {
			str_append(str, set_str_expanded(value));
			return 1;
		}
		i_assert(value->prefixed_str[0] == CONFIG_VALUE_PREFIX_SET_UNEXPANDED);
		/* chained $variables */
		string_t *substr = t_str_new(128);
		if (config_write_keyvariable(ctx, filter_parser,
					     key, value->prefixed_str + 1,
					     substr, FALSE) < 0)
			return -1;
		i_assert(str_c(substr)[0] == CONFIG_VALUE_PREFIX_EXPANDED);
		str_append(str, str_c(substr) + 1);
		return 1;
	}

	if (filter_parser->parent == NULL) {
		/* use the default setting */
		const void *value = CONST_PTR_OFFSET(l->info->defaults,
						     def->offset);
		if (!config_export_type(str, value, def->type))
			i_unreached();
		return 1;
	}

	/* not changed by this parser. maybe parent has. */
	return config_filter_get_value(ctx, filter_parser->parent, def,
				       config_key, key, str);
}

static int
config_get_value(struct config_parser_context *ctx,
		 struct config_filter_parser *filter_parser,
		 struct config_parser_key *config_key,
		 const char *key, string_t *str)
{
	const struct setting_define *def =
		&all_infos[config_key->info_idx]->defines[config_key->define_idx];
	if (def->type == SET_STRLIST || def->type == SET_BOOLLIST ||
	    def->type == SET_FILTER_NAME || def->type == SET_FILTER_ARRAY)
		return 0;

	config_parse_fill_reverse_default_siblings(ctx);
	return config_filter_get_value(ctx, filter_parser, def, config_key, key, str);
}

static struct config_filter_parser *
config_filter_parser_find_path_sub(struct config_filter_parser *parent,
				   const char *path, bool done_reverse)
{
	struct config_filter_parser *parser;
	const char *suffix;

	for (parser = parent->children_head; parser != NULL; parser = parser->next) {
		if (!parser->filter.filter_name_array)
			;
		else if (!str_begins(path, parser->filter.filter_name, &suffix))
			;
		else if (suffix[0] == '/')
			return config_filter_parser_find_path_sub(parser, suffix + 1, FALSE);
		else if (suffix[0] == '\0')
			return parser;
	}
	if (parent->reverse_default_sibling != NULL && !done_reverse) {
		return config_filter_parser_find_path_sub(
			parent->reverse_default_sibling, path, TRUE);
	}
	return NULL;
}

static struct config_filter_parser *
config_filter_parser_find_path(struct config_parser_context *ctx,
			       const char *path)
{
	config_parse_fill_reverse_default_siblings(ctx);

	struct config_filter_parser *parser =
		array_idx_elem(&ctx->all_filter_parsers, 0);
	return config_filter_parser_find_path_sub(parser, path, FALSE);
}

static bool config_filter_has_include_group(const struct config_filter *filter)
{
	for (; filter != NULL; filter = filter->parent) {
		if (filter->filter_name_array &&
		    filter->filter_name[0] == SETTINGS_INCLUDE_GROUP_PREFIX)
			return TRUE;
	}
	return FALSE;
}

static bool
setting_value_can_check(const char *value, bool expand_values)
{
	if (strstr(value, "%{") != NULL)
		return FALSE;

	if (!expand_values) {
		if (strstr(value, "$SET:") != NULL ||
		    strstr(value, "$ENV:") != NULL)
			return FALSE;
	}
	return TRUE;
}

static int
settings_value_check(struct config_parser_context *ctx,
		     const struct setting_parser_info *info,
		     const struct setting_define *def,
		     const char *prefixed_value)
{
	const char *error;

	if (prefixed_value[0] != CONFIG_VALUE_PREFIX_EXPANDED)
		return 0;
	const char *value = prefixed_value + 1;

	switch (def->type) {
	case SET_BOOL: {
		bool b;
		if (!setting_value_can_check(value, ctx->expand_values))
			break;
		if (str_parse_get_bool(value, &b, &error) < 0) {
			ctx->error = p_strdup(ctx->pool, error);
			return -1;
		}
		break;
	}
	case SET_UINTMAX: {
		uintmax_t num;

		if (!setting_value_can_check(value, ctx->expand_values))
			break;
		if (str_to_uintmax(value, &num) < 0) {
			ctx->error = p_strdup_printf(ctx->pool,
				"Invalid number %s: %s", value,
				str_num_error(value));
			return -1;
		}
		break;
	}
	case SET_UINT_OCT:
		if (*value == '0') {
			unsigned long long octal;
			if (!setting_value_can_check(value, ctx->expand_values))
				break;
			if (str_to_ullong_oct(value, &octal) < 0) {
				ctx->error = p_strconcat(ctx->pool,
					"Invalid number: ", value, NULL);
				return -1;
			}
			break;
		}
		/* fall through */
	case SET_UINT: {
		unsigned int num;

		if (!setting_value_can_check(value, ctx->expand_values))
			break;
		if (settings_value_is_unlimited(value))
			break;
		if (str_to_uint(value, &num) < 0) {
			ctx->error = p_strdup_printf(ctx->pool,
				"Invalid number %s: %s", value,
				str_num_error(value));
			return -1;
		}
		break;
	}
	case SET_TIME: {
		unsigned int interval;
		if (!setting_value_can_check(value, ctx->expand_values))
			break;
		if (settings_value_is_unlimited(value))
			break;
		if (str_parse_get_interval(value, &interval, &error) < 0) {
			ctx->error = p_strdup(ctx->pool, error);
			return -1;
		}
		break;
	}
	case SET_TIME_MSECS: {
		unsigned int interval;
		if (!setting_value_can_check(value, ctx->expand_values))
			break;
		if (settings_value_is_unlimited(value))
			break;
		if (str_parse_get_interval_msecs(value, &interval, &error) < 0) {
			ctx->error = p_strdup(ctx->pool, error);
			return -1;
		}
		break;
	}
	case SET_SIZE: {
		uoff_t size;
		if (!setting_value_can_check(value, ctx->expand_values))
			break;
		if (settings_value_is_unlimited(value))
			break;
		if (str_parse_get_size(value, &size, &error) < 0) {
			ctx->error = p_strdup(ctx->pool, error);
			return -1;
		}
		break;
	}
	case SET_IN_PORT: {
		in_port_t port;
		if (!setting_value_can_check(value, ctx->expand_values))
			break;
		if (net_str2port_zero(value, &port) < 0) {
			ctx->error = p_strdup_printf(ctx->pool,
				"Invalid port number %s", value);
			return -1;
		}
		break;
	}
	case SET_STR:
	case SET_STR_NOVARS:
		break;
	case SET_ENUM:
		/* get the available values from default string */
		if (!setting_value_can_check(value, ctx->expand_values))
			break;
		i_assert(info->defaults != NULL);
		const char *const *default_value =
			CONST_PTR_OFFSET(info->defaults, def->offset);
		const char *const *valid_values = t_strsplit(*default_value, ":");
		if (!str_array_find(valid_values, value)) {
			ctx->error = p_strconcat(ctx->pool, "Invalid value: ",
						 value, NULL);
			return -1;
		}
		break;
	case SET_FILE:
		break;
	case SET_STRLIST:
	case SET_BOOLLIST:
	case SET_FILTER_ARRAY:
		break;
	case SET_FILTER_NAME:
		ctx->error = p_strdup_printf(ctx->pool,
			"Setting is a named filter, use '%s {'", def->key);
		return -1;
	case SET_ALIAS:
		i_unreached();
	}
	return 0;
}

static bool
config_is_filter_name(struct config_parser_context *ctx, const char *key,
		      const struct setting_parser_info **info_r,
		      const struct setting_define **def_r)
{
	struct config_parser_key *config_key;
	const struct setting_define *def;

	config_key = hash_table_lookup(ctx->all_keys, key);
	if (config_key == NULL)
		return FALSE;

	def = &all_infos[config_key->info_idx]->defines[config_key->define_idx];
	if (def->type != SET_FILTER_NAME &&
	    def->type != SET_FILTER_ARRAY)
		return FALSE;

	*info_r = all_infos[config_key->info_idx];
	*def_r = def;
	return TRUE;
}

static void
config_list_add_defaults(struct config_parser_context *ctx,
			 struct config_parser_key *config_key,
			 ARRAY_TYPE(const_string) *dest)
{
	struct config_filter filter = ctx->cur_section->filter_parser->filter;
	if (filter.default_settings)
		return;

	filter.default_settings = TRUE;
	struct config_filter_parser *defaults_filter =
		config_filter_parser_find(ctx, &filter);
	if (defaults_filter == NULL)
		return;

	struct config_module_parser *ldef =
		&defaults_filter->module_parsers[config_key->info_idx];
	if (ldef->settings == NULL)
		return;

	const ARRAY_TYPE(const_string) *src =
		ldef->settings[config_key->define_idx].list.prefixed_values;
	if (src != NULL && array_is_created(src))
		array_append_array(dest, src);
}

static int config_apply_strlist(struct config_parser_context *ctx,
				const char *key,
				const char *prefixed_value,
				struct config_parser_key *config_key,
				ARRAY_TYPE(const_string) **strlistp,
				bool *stop_list)
{
	const char *suffix;

	suffix = strchr(key, SETTINGS_SEPARATOR);
	if (suffix == NULL) {
		if (prefixed_value[0] == CONFIG_VALUE_PREFIX_EXPANDED &&
		    prefixed_value[1] == '\0') {
			/* clear out the whole strlist */
			if (*strlistp != NULL)
				array_clear(*strlistp);
			else {
				*strlistp = p_new(ctx->pool,
						  ARRAY_TYPE(const_string), 1);
				p_array_init(*strlistp, ctx->pool, 5);
			}
			*stop_list = TRUE;
			return 0;
		}

		ctx->error = p_strdup_printf(ctx->pool,
			"Setting is a string list, use '%s {'", key);
		return -1;
	}
	key = suffix + 1;

	if (*strlistp == NULL) {
		*strlistp = p_new(ctx->pool, ARRAY_TYPE(const_string), 1);
		p_array_init(*strlistp, ctx->pool, 5);
		config_list_add_defaults(ctx, config_key, *strlistp);
	}

	prefixed_value = p_strdup(ctx->pool, prefixed_value);

	/* replace if it already exists */
	unsigned int i, count;
	const char *const *items = array_get(*strlistp, &count);
	for (i = 0; i < count; i += 2) {
		if (strcmp(items[i] + 1, key) == 0) {
			array_idx_set(*strlistp, i + 1, &prefixed_value);
			return 0;
		}
	}

	string_t *str = t_str_new(64);
	if (config_write_keyvariable(ctx, ctx->cur_section->filter_parser,
				     "", key, str, TRUE) < 0)
		return -1;

	const char *prefixed_key = p_strdup(ctx->pool, str_c(str));
	array_push_back(*strlistp, &prefixed_key);
	array_push_back(*strlistp, &prefixed_value);
	return 0;
}

static int config_apply_boollist(struct config_parser_context *ctx,
				 const char *key, const char *prefixed_value,
				 struct config_parser_key *config_key,
				 ARRAY_TYPE(const_string) **strlistp,
				 bool *stop_list)
{
	ARRAY_TYPE(const_string) boollist;
	const char *error;
	bool b;

	if (strchr(key, SETTINGS_SEPARATOR) != NULL) {
		if (prefixed_value[0] == CONFIG_VALUE_PREFIX_EXPANDED &&
		    setting_value_can_check(prefixed_value + 1,
					    ctx->expand_values) &&
		    str_parse_get_bool(prefixed_value + 1, &b, &error) < 0) {
			ctx->error = p_strdup(ctx->pool, error);
			return -1;
		}
		/* Preserve stop_list's original value. We may be updating a
		   list within the same filter, and the previous setting might
		   have wanted to stop the list already. */
		return config_apply_strlist(ctx, key, prefixed_value,
					    config_key, strlistp, stop_list);
	}

	/* replace the whole list */
	t_array_init(&boollist, 16);
	if (settings_parse_boollist_string(prefixed_value + 1, ctx->pool,
					   &boollist, &error) < 0) {
		ctx->error = p_strdup(ctx->pool, error);
		return -1;
	}
	if (*strlistp == NULL) {
		*strlistp = p_new(ctx->pool, ARRAY_TYPE(const_string), 1);
		p_array_init(*strlistp, ctx->pool, array_count(&boollist));
	} else {
		array_clear(*strlistp);
	}

	string_t *str = t_str_new(64);
	const char *yes = CONFIG_VALUE_PREFIX_EXPANDED_S"yes";
	array_foreach_elem(&boollist, key) {
		str_truncate(str, 0);
		if (config_write_keyvariable(ctx, ctx->cur_section->filter_parser,
					     "", key, str, TRUE) < 0)
			return -1;
		const char *prefixed_key = p_strdup(ctx->pool, str_c(str));
		array_push_back(*strlistp, &prefixed_key);
		array_push_back(*strlistp, &yes);
	}
	*stop_list = TRUE;
	return 0;
}

static int config_apply_filter_array(struct config_parser_context *ctx,
				     const struct config_line *line,
				     const char *value,
				     ARRAY_TYPE(const_string) **namesp)
{
	const char *const *list =
		t_strsplit(value, SETTINGS_FILTER_ARRAY_SEPARATORS);
	unsigned int i, count = str_array_length(list);

	if (line != NULL && line->type != CONFIG_LINE_TYPE_SECTION_BEGIN) {
		ctx->error = p_strdup_printf(ctx->pool,
			"Setting is a named list filter, use '%s %s {'",
			line->key, value);
		return -1;
	}

	if (*namesp == NULL) {
		*namesp = p_new(ctx->pool, ARRAY_TYPE(const_string), 1);
		p_array_init(*namesp, ctx->pool, count);
	}

	for (i = 0; i < count; i++) {
		const char *value =
			p_strdup(ctx->pool, settings_section_unescape(list[i]));
		array_push_back(*namesp, &value);
	}
	return 0;
}

static int config_apply_file(struct config_parser_context *ctx,
			     const struct config_line *line,
			     const char *path, const char **prefixed_output_r)
{
	struct stat st;
	const char *full_path, *error;

	if (path[0] == '\0') {
		*prefixed_output_r = CONFIG_VALUE_PREFIX_EXPANDED_S;
		return 0;
	}

	/* Do not attempt to expand paths that contain variable expansions.
	   These will be expanded later. */
	if (!ctx->expand_values || strstr(path, "%{") != NULL) {
		*prefixed_output_r = p_strdup_printf(ctx->pool, "%c%s",
			CONFIG_VALUE_PREFIX_EXPANDED, path);
		return 0;
	}
	full_path = fix_relative_path(path, ctx->cur_input);
	/* preserve original relative path in doveconf output */
	if (full_path != path && ctx->expand_values)
		path = full_path;
	if (settings_parse_read_file(full_path, path, ctx->pool, &st,
				     CONFIG_VALUE_PREFIX_EXPANDED_S,
				     prefixed_output_r, &error) < 0) {
		ctx->error = p_strdup(ctx->pool, error);
		if (config_apply_error(ctx, line->key) < 0)
			return -1;
		/* delayed error */
		*prefixed_output_r = CONFIG_VALUE_PREFIX_EXPANDED_S;
	} else {
		config_parser_add_seen_file(ctx, &st, full_path);
	}
	return 0;
}

static int
config_apply_exact_line(struct config_parser_context *ctx,
			const struct config_line *line,
			const char *key, const char *prefixed_value)
{
	struct config_parser_key *config_key;

	if (ctx->cur_section->filter_def != NULL &&
	    !ctx->cur_section->filter_parser->filter_required_setting_seen &&
	    ctx->cur_section->filter_def->required_setting != NULL &&
	    strcmp(key, ctx->cur_section->filter_def->required_setting) == 0)
		ctx->cur_section->filter_parser->filter_required_setting_seen = TRUE;

	/* if key is list/key, lookup only "list" */
	const char *lookup_key = t_strcut(key, '/');
	config_key = hash_table_lookup(ctx->all_keys, lookup_key);
	if (config_key == NULL)
		return 0;

	/* FIXME: These don't work because config_parsed_get_setting() doesn't
	   expand groups. Maybe not worth the effort to fix it? */
	if ((strcmp(lookup_key, "import_environment") == 0 ||
	     strcmp(lookup_key, "base_dir") == 0 ||
	     strcmp(lookup_key, "dovecot_storage_version") == 0) &&
	    config_filter_has_include_group(&ctx->cur_section->filter_parser->filter)) {
		ctx->error = p_strdup_printf(ctx->pool,
			"%s cannot currently be defined inside groups", lookup_key);
		return -1;
	}

	for (; config_key != NULL; config_key = config_key->next) {
		struct config_module_parser *l =
			&ctx->cur_section->filter_parser->module_parsers[config_key->info_idx];
		if (l->settings == NULL) {
			config_module_parser_init(ctx, l);
			i_assert(l->settings != NULL);
		}
		switch (l->info->defines[config_key->define_idx].type) {
		case SET_STRLIST:
			if (config_apply_strlist(ctx, key, prefixed_value, config_key,
					&l->settings[config_key->define_idx].list.prefixed_values,
					&l->settings[config_key->define_idx].list.stop_list) < 0)
				return -1;
			break;
		case SET_BOOLLIST:
			if (config_apply_boollist(ctx, key, prefixed_value, config_key,
					&l->settings[config_key->define_idx].list.prefixed_values,
					&l->settings[config_key->define_idx].list.stop_list) < 0)
				return -1;
			break;
		case SET_FILTER_ARRAY:
			if (prefixed_value[0] != CONFIG_VALUE_PREFIX_EXPANDED) {
				i_assert(prefixed_value[0] == CONFIG_VALUE_PREFIX_SET_UNEXPANDED);
				ctx->error = p_strdup_printf(ctx->pool,
					"Named list filter name must not contain $SET: %s",
					prefixed_value + 1);
				return -1;
			}
			const char *value = prefixed_value + 1;
			if (str_begins_with(value, "__")) {
				/* These are reserved for internal filters */
				ctx->error = p_strdup_printf(ctx->pool,
					"Named list filter name must not begin with '__': %s",
					value);
				return -1;
			}
			if (config_apply_filter_array(ctx, line, value,
					&l->settings[config_key->define_idx].filter_array) < 0)
				return -1;
			break;
		case SET_FILE: {
			const char *inline_value;
			if (prefixed_value[0] != CONFIG_VALUE_PREFIX_EXPANDED) {
				/* FIXME: implement in a later commit */
				i_assert(prefixed_value[0] == CONFIG_VALUE_PREFIX_SET_UNEXPANDED);
				ctx->error = p_strdup_printf(ctx->pool,
					"File settings must not contain $SET: %s",
					prefixed_value + 1);
				return -1;
			}
			const char *value = prefixed_value + 1;
			if (str_begins(value, SET_FILE_INLINE_PREFIX,
				       &inline_value)) {
				l->settings[config_key->define_idx].prefixed_str =
					value[0] == '\0' ? CONFIG_VALUE_PREFIX_EXPANDED_S :
					p_strdup_printf(ctx->pool, "%c\n%s",
							CONFIG_VALUE_PREFIX_EXPANDED,
							inline_value);
				break;
			}
			i_assert(line != NULL);
			if (config_apply_file(ctx, line, value,
					&l->settings[config_key->define_idx].prefixed_str) < 0)
				return -1;
			break;
		}
		default:
			l->settings[config_key->define_idx].prefixed_str =
				p_strdup(ctx->pool, prefixed_value);
			break;
		}
		if (l->change_counters[config_key->define_idx] < ctx->change_counter) {
			l->change_counters[config_key->define_idx] =
				ctx->change_counter;
		}
		if (settings_value_check(ctx, l->info,
				&l->info->defines[config_key->define_idx],
				prefixed_value) < 0)
			return -1;
		/* FIXME: remove once auth does support these. */
		if (strcmp(l->info->name, "auth") == 0 &&
		    config_parser_is_in_localremote(ctx->cur_section)) {
			ctx->error = p_strconcat(ctx->pool,
				"Auth settings not supported inside local/remote blocks: ",
				key, NULL);
			return -1;
		}
	}
	return 1;
}

static bool replace_filter_prefix(struct config_parser_context *ctx,
				  const char **key)
{
	/* doveconf human-readable output only: replace filter_name_key with
	   filter_name/key so it shows up inside filter_name { key } */
	unsigned int filter_name_idx;
	bsearch_insert_pos(key, ctx->filter_name_prefixes,
			   ctx->filter_name_prefixes_count,
			   sizeof(ctx->filter_name_prefixes[0]),
			   i_strcmp_p, &filter_name_idx);
	/* Insert position might not be exactly the place we want to look at.
	   For example:

	   *key = "foo_3"
	   filter_name_prefixes[filter_name_idx-1] = "foo_2"
	   filter_name_prefixes[filter_name_idx-2] = "foo_"

	   In this case we want to use the "foo_" prefix.
	*/
	const char *key_minimum_prefix = t_strcut(*key, '_');
	for (; filter_name_idx > 0; filter_name_idx--) {
		const char *filter_name_prefix =
			ctx->filter_name_prefixes[filter_name_idx-1];
		size_t filter_name_prefix_len = strlen(filter_name_prefix);
		if (strncmp(*key, filter_name_prefix, filter_name_prefix_len) != 0) {
			if (strcmp(key_minimum_prefix, filter_name_prefix) > 0)
				break;
			/* Previous prefixes could still match. */
			continue;
		}

		const char *cur_filter_name =
			ctx->cur_section->filter_parser->filter.filter_name;
		if (cur_filter_name != NULL)
			cur_filter_name = t_str_replace(cur_filter_name, '/', '_');
		if (cur_filter_name != NULL &&
		    strncmp(filter_name_prefix, cur_filter_name,
			    filter_name_prefix_len - 1) == 0 &&
		    cur_filter_name[filter_name_prefix_len-1] == '\0') {
			/* already inside the correct filter, e.g.
			   userdb ldap { iterate_fields doesn't need
			   userdb_ldap { named filter in the middle. */
			return FALSE;
		}

		*key = t_strdup_printf("%.*s/%s", (int)filter_name_prefix_len-1,
				       filter_name_prefix, *key);
		return TRUE;
	}
	return FALSE;
}

static const char *filter_key_skip_group_prefix(const char *key)
{
	return key[0] == SETTINGS_INCLUDE_GROUP_PREFIX ? key + 1 : key;
}

static bool
config_key_can_autoprefix(struct config_parser_context *ctx, const char *key)
{
	const char *lookup_key = t_strcut(key, '/');
	struct config_parser_key *config_key =
		hash_table_lookup(ctx->all_keys, lookup_key);
	if (config_key == NULL)
		return FALSE;

	const struct setting_define *def =
		&all_infos[config_key->info_idx]->defines[config_key->define_idx];
	/* named filters aren't useful for autoprefixing, and they can in
	   some cases cause conflicts. For example foo .. { fs .. { .. } }
	   can fail if there is "foo_fs" named filter also. */
	return def->type != SET_FILTER_NAME;
}

static void
config_set_unknown_key_error(struct config_parser_context *ctx, const char *key)
{
	string_t *errstr = t_str_new(128);
	str_printfa(errstr, "Unknown setting: %s", key);

	const char *filter_name =
		ctx->cur_section->filter_parser->filter.filter_name;
	if (filter_name == NULL) {
		ctx->error = p_strdup(ctx->pool, str_c(errstr));
		return;
	}
	const char *filter_name_key = t_strcut(filter_name, '/');
	str_printfa(errstr, " (%s_%s", filter_name_key, key);
	if (ctx->cur_section->filter_parser->filter.filter_name_array) {
		str_printfa(errstr, " or %s_%s",
			    t_str_replace(filter_name, '/', '_'), key);
	}
	str_append(errstr, " not found either.");
	if (!ctx->cur_section->filter_parser->filter.filter_name_array) {
		str_append_c(errstr, ')');
		ctx->error = p_strdup(ctx->pool, str_c(errstr));
		return;
	}

	/* Perhaps autoprefixing didn't work as expected with a named list
	   filter. For example passdb static2 { password } - try to find
	   passdb_*_password and suggest using that. */
	string_t *alt_keys = t_str_new(128);
	const char *prefix = t_strconcat(filter_name_key, "_", NULL);
	struct hash_iterate_context *iter =
		hash_table_iterate_init(ctx->all_keys);
	const char *hash_key, *suffix;
	struct config_parser_key *config_key;
	unsigned int found_count = 0;
	while (hash_table_iterate(iter, ctx->all_keys, &hash_key, &config_key)) {
		if (!str_begins(hash_key, prefix, &suffix))
			continue;
		/* Skip over the next element. Don't skip over multiple '_'
		   since there are no settings where that would match. */
		while (*suffix != '_' && *suffix != '\0')
			suffix++;
		/* the rest should match the key */
		if (suffix[0] == '_' && strcmp(suffix + 1, key) == 0) {
			if (str_len(alt_keys) > 0)
				str_append(alt_keys, ", ");
			str_append(alt_keys, hash_key);
			found_count++;
		}

	}
	hash_table_iterate_deinit(&iter);
	if (found_count == 0)
		str_append_c(errstr, ')');
	else if (found_count == 1)
		str_printfa(errstr, " Did you mean %s?)", str_c(alt_keys));
	else {
		str_printfa(errstr, " Did you mean one of: %s?)",
			    str_c(alt_keys));
	}
	ctx->error = p_strdup(ctx->pool, str_c(errstr));
}

static int
config_apply_line_full(struct config_parser_context *ctx,
		       const struct config_line *line,
		       const char *key_with_path,
		       const char *prefixed_value, const char **full_key_r,
		       bool autoprefix, bool *root_setting_r)
{
	struct config_filter_parser *filter_parser, *orig_filter_parser;
	const char *p, *key;
	int ret = 0;

	orig_filter_parser = ctx->cur_section->filter_parser;
again:
	while ((p = strchr(key_with_path, '/')) != NULL) {
		/* Support e.g. service/imap/inet_listener/imap/ or auth_policy/
		   prefix here. These prefixes are used by default settings and
		   old-set-parser. */
		struct config_filter filter = {
			.parent = &ctx->cur_section->filter_parser->filter,
			.default_settings = (ctx->change_counter ==
					     CONFIG_PARSER_CHANGE_DEFAULTS),
		};
		/* find the type of the first prefix/ */
		filter.filter_name = t_strdup_until(key_with_path, p);
		struct config_parser_key *config_key =
			hash_table_lookup(ctx->all_keys, filter.filter_name);
		if (config_key == NULL)
			break;
		struct config_module_parser *l =
			&ctx->cur_section->filter_parser->module_parsers[config_key->info_idx];

		const char *p2 = NULL;
		if (l->info->defines[config_key->define_idx].type == SET_FILTER_ARRAY &&
		    (p2 = strchr(p + 1, '/')) != NULL) {
			/* We have prefix/name/ */
			filter.filter_name = t_strdup_until(key_with_path, p2);
			filter.filter_name_array = TRUE;
		}

		filter_parser = config_filter_parser_find(ctx, &filter);
		if (filter_parser == NULL) {
			/* Verify that this is a filter_name/ prefix. If not,
			   it should be a list/ */
			if (l->info->defines[config_key->define_idx].type != SET_FILTER_NAME &&
			    l->info->defines[config_key->define_idx].type != SET_FILTER_ARRAY)
				break;

			filter.filter_name =
				p_strdup(ctx->pool, filter.filter_name);
			ctx->cur_section->filter_parser =
				config_add_new_parser(ctx, &filter,
					ctx->cur_section->filter_parser);
		} else {
			ctx->cur_section->filter_parser = filter_parser;
		}
		if (!filter.filter_name_array)
			key_with_path = p + 1;
		else {
			i_assert(p2 != NULL);
			key_with_path = p2 + 1;
		}
	}

	if (ctx->filter_name_prefixes_count > 0 &&
	    replace_filter_prefix(ctx, &key_with_path))
		goto again;

	/* the only '/' left should be if key is under list/ */
	key = key_with_path;

	if (ctx->cur_section->filter_parser->filter.filter_name_array) {
		/* For named list filters, try filter name { key } ->
		   filter_name_key first before anything else. */
		i_assert(ctx->cur_section->filter_parser->filter.filter_name != NULL);
		const char *filter_key = filter_key_skip_group_prefix(
			t_str_replace(ctx->cur_section->filter_parser->filter.filter_name, '/', '_'));
		const char *key2 = t_strdup_printf("%s_%s", filter_key, key);
		struct config_filter_parser *last_filter_parser =
			ctx->cur_section->filter_parser;

		ret = !config_key_can_autoprefix(ctx, key2) ? 0 :
			config_apply_exact_line(ctx, line, key2, prefixed_value);
		if (ret > 0 && full_key_r != NULL) {
			*full_key_r = key2;
			*root_setting_r = config_filter_is_empty(
				&ctx->cur_section->filter_parser->filter);
		}
		ctx->cur_section->filter_parser = last_filter_parser;
	}
	if (ret == 0 && autoprefix &&
	    ctx->cur_section->filter_parser->filter.filter_name != NULL) {
		/* first try the filter name-specific prefix, so e.g.
		   inet_listener { ssl=yes } won't try to change the global
		   ssl setting. */
		const char *filter_key = filter_key_skip_group_prefix(
			t_strcut(ctx->cur_section->filter_parser->filter.filter_name, '/'));
		const char *key2 = t_strdup_printf("%s_%s", filter_key, key);
		struct config_filter_parser *last_filter_parser =
			ctx->cur_section->filter_parser;
		if (!ctx->cur_section->filter_parser->filter.filter_name_array &&
		    ctx->filter_name_prefixes_count == 0) {
			/* For named non-list filters, if the setting name
			   prefix equals the filter name, change the setting
			   outside the filter. Otherwise it's rather confusing
			   if foo_key=value is different from foo { key=value }.
			   Also the latter would require settings_get() call to
			   have "foo" filter named enabled in the event to be
			   able to get foo_key's value, which isn't always done
			   (or useful, or easy). */
			ctx->cur_section->filter_parser =
				ctx->cur_section->filter_parser->parent;
			const char *suffix;
			if (str_begins(key, filter_key, &suffix) &&
			    suffix[0] == '_') {
				/* don't try filter_filter_key, but do apply
				   filter_key to the parent filter_parser */
				key2 = key;
			}
		}
		ret = !config_key_can_autoprefix(ctx, key2) ? 0 :
			config_apply_exact_line(ctx, line, key2, prefixed_value);
		if (ret > 0 && full_key_r != NULL) {
			*full_key_r = key2;
			*root_setting_r = config_filter_is_empty(
				&ctx->cur_section->filter_parser->filter);
		}
		ctx->cur_section->filter_parser = last_filter_parser;
	}
	if (ret == 0) {
		ret = config_apply_exact_line(ctx, line, key, prefixed_value);
		if (full_key_r != NULL) {
			*root_setting_r = config_filter_is_empty(
				&ctx->cur_section->filter_parser->filter);
			*full_key_r = key;
		}
	}
	ctx->cur_section->filter_parser = orig_filter_parser;
	if (ret == 0) {
		if ((ctx->flags & CONFIG_PARSE_FLAG_IGNORE_UNKNOWN) != 0)
			return 0;
		config_set_unknown_key_error(ctx, key);
		return -1;
	}
	return ret < 0 ? -1 : 0;
}

int config_apply_key_value(struct config_parser_context *ctx,
			   const char *key_with_path,
			   const char *value, const char **full_key_r)
{
	bool root_setting;
	const char *prefixed_value =
		t_strdup_printf("%c%s", CONFIG_VALUE_PREFIX_EXPANDED, value);
	return config_apply_line_full(ctx, NULL, key_with_path,
				      prefixed_value, full_key_r,
				      TRUE, &root_setting);
}

static struct config_module_parser *
config_module_parsers_init(pool_t pool)
{
	struct config_module_parser *dest;
	unsigned int i, count;

	for (count = 0; all_infos[count] != NULL; count++) ;

	dest = p_new(pool, struct config_module_parser, count + 1);
	for (i = 0; i < count; i++) {
		/* create parser lazily */
		dest[i].info = all_infos[i];
	}
	return dest;
}

static struct config_filter_parser *
config_add_new_parser(struct config_parser_context *ctx,
		      const struct config_filter *filter,
		      struct config_filter_parser *parent_filter_parser)
{
	struct config_filter_parser *filter_parser;

	filter_parser = p_new(ctx->pool, struct config_filter_parser, 1);
	filter_parser->create_order = ctx->create_order_counter++;
	filter_parser->filter = *filter;
	filter_parser->module_parsers =
		parent_filter_parser == NULL && !filter->default_settings ?
		ctx->root_module_parsers :
		config_module_parsers_init(ctx->pool);
	array_push_back(&ctx->all_filter_parsers, &filter_parser);
	ctx->reverse_parsers_set = FALSE;

	if (ctx->all_filter_parsers_hash._table != NULL) {
		hash_table_insert(ctx->all_filter_parsers_hash,
				  &filter_parser->filter, filter_parser);
	}

	if (parent_filter_parser != NULL) {
		filter_parser->parent = parent_filter_parser;
		filter_parser->named_list_filter_count =
			parent_filter_parser->named_list_filter_count;
		filter_parser->named_filter_count =
			parent_filter_parser->named_filter_count;
		if (filter->filter_name_array)
			filter_parser->named_list_filter_count++;
		else if (filter->filter_name != NULL)
			filter_parser->named_filter_count++;
		DLLIST2_APPEND(&parent_filter_parser->children_head,
			       &parent_filter_parser->children_tail,
			       filter_parser);
	}

	return filter_parser;
}

static struct config_section_stack *
config_add_new_section(struct config_parser_context *ctx)
{
	struct config_section_stack *section;

	section = p_new(ctx->pool, struct config_section_stack, 1);
	section->prev = ctx->cur_section;
	section->filter_parser = ctx->cur_section->filter_parser;

	section->open_path = p_strdup(ctx->pool, ctx->cur_input->path);
	section->open_linenum = ctx->cur_input->linenum;
	return section;
}

static struct config_filter_parser *
config_filter_parser_find(struct config_parser_context *ctx,
			  const struct config_filter *filter)
{
	return hash_table_lookup(ctx->all_filter_parsers_hash, filter);
}

static struct config_filter_parser *
config_filter_parser_find_slow(struct config_parser_context *ctx,
			       const struct config_filter *filter)
{
	struct config_filter_parser *filter_parser;

	array_foreach_elem(&ctx->all_filter_parsers, filter_parser) {
		if (config_filters_equal(&filter_parser->filter, filter))
			return filter_parser;
	}
	return NULL;
}

int config_parse_net(const char *value, struct ip_addr *ip_r,
		     unsigned int *bits_r, const char **error_r)
{
	struct ip_addr *ips;
	const char *p;
	unsigned int ip_count, bits, max_bits;
	time_t t1, t2;
	int ret;

	if (net_parse_range(value, ip_r, bits_r) == 0)
		return 0;

	p = strchr(value, '/');
	if (p != NULL) {
		value = t_strdup_until(value, p);
		p++;
	}

	t1 = time(NULL);
	alarm(DNS_LOOKUP_TIMEOUT_SECS);
	ret = net_gethostbyname(value, &ips, &ip_count);
	alarm(0);
	t2 = time(NULL);
	if (ret != 0) {
		*error_r = t_strdup_printf("gethostbyname(%s) failed: %s",
					   value, net_gethosterror(ret));
		return -1;
	}
	*ip_r = ips[0];

	if (t2 - t1 >= DNS_LOOKUP_WARN_SECS) {
		i_warning("gethostbyname(%s) took %d seconds",
			  value, (int)(t2-t1));
	}

	max_bits = IPADDR_IS_V4(&ips[0]) ? 32 : 128;
	if (p == NULL)
		*bits_r = max_bits;
	else if (str_to_uint(p, &bits) == 0 && bits <= max_bits)
		*bits_r = bits;
	else {
		*error_r = t_strdup_printf("Invalid network mask: %s", p);
		return -1;
	}
	return 0;
}

int config_filter_parse(struct config_filter *filter, pool_t pool,
			const char *key, const char *value,
			const char **error_r)
{
	struct config_filter *parent = filter->parent;
	const char *error;

	*error_r = NULL;

	if (key[0] == SETTINGS_INCLUDE_GROUP_PREFIX) {
		if (!config_filter_is_empty(parent) &&
		    !config_filter_is_empty_defaults(parent)) {
			*error_r = "groups must defined at top-level, not under filters";
			return -1;
		}
		filter->filter_name =
			p_strdup_printf(pool, "%s/%s", key, value);
		filter->filter_name_array = TRUE;
	} else if (strcmp(key, "protocol") == 0) {
		if (parent->protocol != NULL)
			*error_r = "Nested protocol { protocol { .. } } block not allowed";
		else if (parent->filter_name != NULL)
			*error_r = t_strdup_printf(
				"%s { protocol { .. } } not allowed (use protocol { %s { .. } } instead)",
				t_strcut(parent->filter_name, '/'),
				t_strcut(parent->filter_name, '/'));
		else
			filter->protocol = p_strdup(pool, value);
	} else if (strcmp(key, "local") == 0) {
		if (parent->remote_bits > 0)
			*error_r = "remote { local { .. } } not allowed (use local { remote { .. } } instead)";
		else if (parent->protocol != NULL)
			*error_r = "protocol { local { .. } } not allowed (use local { protocol { .. } } instead)";
		else if (parent->local_name != NULL)
			*error_r = "local_name { local { .. } } not allowed (use local { local_name { .. } } instead)";
		else if (parent->filter_name != NULL)
			*error_r = p_strdup_printf(pool,
				"%s { local { .. } } not allowed (use local { %s { .. } } instead)",
				t_strcut(parent->filter_name, '/'),
				t_strcut(parent->filter_name, '/'));
		else if (config_parse_net(value, &filter->local_net,
					  &filter->local_bits, &error) < 0)
			*error_r = p_strdup(pool, error);
		else if (parent->local_bits > filter->local_bits ||
			 (parent->local_bits > 0 &&
			  !net_is_in_network(&filter->local_net,
					     &parent->local_net,
					     parent->local_bits)))
			*error_r = "local net1 { local net2 { .. } } requires net2 to be inside net1";
		else
			filter->local_host = p_strdup(pool, value);
	} else if (strcmp(key, "local_name") == 0) {
		if (strchr(value, ' ') != NULL)
			*error_r = "Multiple names no longer supported in local_name value";
		else if (parent->remote_bits > 0)
			*error_r = "remote { local_name { .. } } not allowed (use local_name { remote { .. } } instead)";
		else if (parent->protocol != NULL)
			*error_r = "protocol { local_name { .. } } not allowed (use local_name { protocol { .. } } instead)";
		else if (parent->filter_name != NULL)
			*error_r = p_strdup_printf(pool,
				"%s { local_name { .. } } not allowed (use local_name { %s { .. } } instead)",
				t_strcut(parent->filter_name, '/'),
				t_strcut(parent->filter_name, '/'));
		else
			filter->local_name = p_strdup(pool, t_str_lcase(value));
	} else if (strcmp(key, "remote") == 0) {
		if (parent->protocol != NULL)
			*error_r = "protocol { remote { .. } } not allowed (use remote { protocol { .. } } instead)";
		else if (parent->filter_name != NULL)
			*error_r = p_strdup_printf(pool,
				"%s { remote { .. } } not allowed (use remote { %s { .. } } instead)",
				t_strcut(parent->filter_name, '/'),
				t_strcut(parent->filter_name, '/'));
		else if (config_parse_net(value, &filter->remote_net,
					  &filter->remote_bits, &error) < 0)
			*error_r = p_strdup(pool, error);
		else if (parent->remote_bits > filter->remote_bits ||
			 (parent->remote_bits > 0 &&
			  !net_is_in_network(&filter->remote_net,
					     &parent->remote_net,
					     parent->remote_bits)))
			*error_r = "remote net1 { remote net2 { .. } } requires net2 to be inside net1";
		else
			filter->remote_host = p_strdup(pool, value);
	} else {
		return 0;
	}
	return *error_r == NULL ? 1 : -1;
}

static bool
config_filter_add_new_filter(struct config_parser_context *ctx,
			     const char *key, const char *value,
			     bool value_quoted)
{
	struct config_filter filter;
	struct config_filter *parent = &ctx->cur_section->prev->filter_parser->filter;
	struct config_filter_parser *filter_parser;
	const struct setting_parser_info *filter_info = NULL;
	const struct setting_define *filter_def = NULL;
	const char *error;

	i_zero(&filter);
	filter.parent = parent;

	int ret = config_filter_parse(&filter, ctx->pool, key, value, &error);
	if (ret < 0) {
		ctx->error = p_strdup(ctx->pool, error);
		return FALSE;
	}
	if (ret > 0)
		; /* already parsed */
	else if (config_is_filter_name(ctx, key, &filter_info, &filter_def)) {
		if (filter_def->type == SET_FILTER_NAME) {
			if (value[0] != '\0' || value_quoted) {
				ctx->error = p_strdup_printf(ctx->pool,
					"%s { } must not have a section name",
					key);
				return FALSE;
			}
			filter.filter_name = p_strdup(ctx->pool, key);
		} else {
			if (strcmp(key, "namespace") == 0 &&
			    parent->filter_name_array &&
			    (str_begins_with(parent->filter_name, "namespace/") ||
			     str_begins_with(parent->filter_name, "mailbox/"))) {
				ctx->error = p_strdup_printf(ctx->pool,
					"%s { .. } not allowed under %s { .. }",
					key, t_strcut(parent->filter_name, '/'));
				return FALSE;
			}
			if (strcmp(key, "mailbox") == 0 &&
			    parent->filter_name_array &&
			    str_begins_with(parent->filter_name, "mailbox/")) {
				ctx->error = p_strdup_printf(ctx->pool,
					"%s { .. } not allowed under %s { .. }",
					key, t_strcut(parent->filter_name, '/'));
				return FALSE;
			}
			if (strcmp(key, "service") == 0 &&
			    parent->filter_name_array &&
			    parent->filter_name[0] != SETTINGS_INCLUDE_GROUP_PREFIX) {
				ctx->error = p_strdup_printf(ctx->pool,
					"%s { .. } not allowed under %s { .. }",
					key, t_strcut(parent->filter_name, '/'));
				return FALSE;
			}
			if (value[0] == '\0' && !value_quoted) {
				ctx->error = p_strdup_printf(ctx->pool,
					"%s { } is missing section name", key);
				return FALSE;
			}
			filter.filter_name =
				p_strdup_printf(ctx->pool, "%s/%s", key, value);
			filter.filter_name_array = TRUE;
		}
	} else {
		return FALSE;
	}

	filter_parser = config_filter_parser_find(ctx, &filter);
	if (filter_parser != NULL)
		ctx->cur_section->filter_parser = filter_parser;
	else {
		if (filter_def != NULL && filter_def->type == SET_FILTER_ARRAY) {
			/* add it to the list of filter names */
			const char *escaped_value =
				settings_section_escape(value);
			i_assert(filter_info != NULL);
			if (config_apply_key_value(ctx, filter_def->key,
						   escaped_value, NULL) < 0) {
				ctx->error = p_strdup_printf(ctx->pool,
					"Failed to set %s=%s for struct %s: %s",
					filter_def->key, escaped_value,
					filter_info->name, ctx->error);
				return FALSE;
			}
		}
		ctx->cur_section->filter_parser =
			config_add_new_parser(ctx, &filter,
					      ctx->cur_section->filter_parser);
		if (key[0] == SETTINGS_INCLUDE_GROUP_PREFIX) {
			/* This is a group filter's root (which may have child
			   filters) */
			const char *include_group = key + 1;
			struct config_include_group_filters *group =
				hash_table_lookup(ctx->all_include_groups,
						  include_group);
			if (group == NULL) {
				group = p_new(ctx->pool,
					      struct config_include_group_filters, 1);
				group->label = p_strdup(ctx->pool, include_group);
				p_array_init(&group->filters, ctx->pool, 4);
				hash_table_insert(ctx->all_include_groups,
						  group->label, group);
			}
			array_push_back(&group->filters, &ctx->cur_section->filter_parser);
		}
	}
	ctx->cur_section->is_filter = TRUE;

	if (filter_def != NULL) {
		i_assert(filter_info != NULL);
		ctx->cur_section->filter_def = filter_def;
		if (filter_def->type == SET_FILTER_ARRAY) {
			/* add the name field for the filter */
			const char *prefixed_value = t_strdup_printf("%c%s",
				CONFIG_VALUE_PREFIX_EXPANDED, value);
			bool root_setting;
			if (config_apply_line_full(ctx, NULL,
					filter_def->filter_array_field_name,
					prefixed_value, NULL, FALSE,
					&root_setting) < 0) {
				i_panic("BUG: Invalid setting definitions: "
					"Failed to set %s=%s for struct %s: %s",
					filter_def->filter_array_field_name,
					value, filter_info->name, ctx->error);
			}
			struct config_section_stack *prev_section =
				ctx->cur_section->prev;
			if (prev_section->filter_def != NULL &&
			    prev_section->filter_def->required_setting != NULL &&
			    strcmp(key, prev_section->filter_def->required_setting) == 0)
				prev_section->filter_parser->filter_required_setting_seen = TRUE;
		}
	}
	return TRUE;
}

void config_fill_set_parser(struct setting_parser_context *parser,
			    const struct config_module_parser *p,
			    bool expand_values)
{
	if (p->change_counters == NULL)
		return;

	for (unsigned int i = 0; p->info->defines[i].key != NULL; i++) {
		if (p->change_counters[i] == 0)
			continue;

		switch (p->info->defines[i].type) {
		case SET_STRLIST:
		case SET_BOOLLIST: {
			if (p->settings[i].list.prefixed_values == NULL)
				break;
			unsigned int j, count;
			const char *const *prefixed_strings =
				array_get(p->settings[i].list.prefixed_values, &count);
			for (j = 0; j < count; j += 2) T_BEGIN {
				i_assert(prefixed_strings[j][0] == CONFIG_VALUE_PREFIX_EXPANDED);
				i_assert(prefixed_strings[j + 1][0] == CONFIG_VALUE_PREFIX_EXPANDED);
				const char *key = t_strdup_printf("%s/%s",
					p->info->defines[i].key,
					settings_section_escape(prefixed_strings[j] + 1));
				(void)settings_parse_keyidx_value_nodup(parser, i,
					key, prefixed_strings[j + 1] + 1);
			} T_END;
			break;
		}
		case SET_FILTER_ARRAY: {
			const char *name;
			array_foreach_elem(p->settings[i].filter_array, name) T_BEGIN {
				(void)settings_parse_keyidx_value(parser, i,
					p->info->defines[i].key,
					settings_section_escape(name));
			} T_END;
			break;
		}
		default: {
			const char *value = set_str_expanded(&p->settings[i]);
			if (p->info->defines[i].type != SET_STR_NOVARS &&
			    p->info->defines[i].type != SET_FILE &&
			    !setting_value_can_check(set_str_expanded(&p->settings[i]),
						     expand_values)) {
				/* We don't know what the variables would
				   expand to. */
				value = set_value_unknown;
			}
			(void)settings_parse_keyidx_value_nodup(parser, i,
				p->info->defines[i].key, value);
			break;
		}
		}
	}
}

static void
config_filter_parser_check(struct config_parser_context *ctx,
			   struct config_parsed *new_config,
			   struct event *event,
			   struct config_filter_parser *filter_parser)
{
	struct config_module_parser *p, *default_p, *next_default_p;
	const struct config_filter *filter;
	const char *error = NULL;
	pool_t tmp_pool;
	bool ok;

	event = event_create(event);
	if (!ctx->expand_values)
		event_add_str(event, SETTINGS_EVENT_NO_EXPAND, "yes");
	for (filter = &filter_parser->filter; filter != NULL; filter = filter->parent) {
		if (filter->protocol != NULL)
			event_add_str(event, "protocol", filter->protocol);
		if (filter->local_name != NULL)
			event_add_str(event, "local_name", filter->local_name);
		if (filter->local_bits > 0)
			event_add_ip(event, "local_ip", &filter->local_net);
		if (filter->remote_bits > 0)
			event_add_ip(event, "remote_ip", &filter->remote_net);
	}

	/* Defaults are in a separate filter. Merge them with the non-defaults
	   filter before calling check_func()s. */
	struct config_filter default_filter = filter_parser->filter;
	default_filter.default_settings = TRUE;
	struct config_filter_parser *default_filter_parser =
		config_filter_parser_find_slow(ctx, &default_filter);
	default_p = default_filter_parser == NULL ? NULL :
		default_filter_parser->module_parsers;

	tmp_pool = pool_alloconly_create(MEMPOOL_GROWING"config parsers check", 1024);
	for (p = filter_parser->module_parsers; p->info != NULL;
	     p++, default_p = next_default_p) {
		next_default_p = default_p == NULL ? NULL : default_p + 1;
		if (p->settings == NULL)
			continue;

		i_assert(default_p == NULL || default_p->info == p->info);

		p_clear(tmp_pool);
		struct setting_parser_context *tmp_parser =
			settings_parser_init(tmp_pool, p->info,
					     settings_parser_flags);
		if (default_p != NULL) {
			config_fill_set_parser(tmp_parser, default_p,
					       ctx->expand_values);
		}
		config_fill_set_parser(tmp_parser, p, ctx->expand_values);
		T_BEGIN {
			ok = settings_parser_check(tmp_parser, tmp_pool,
						   event, &error);
		} T_END_PASS_STR_IF(!ok, &error);
		settings_parser_unref(&tmp_parser);

		if (!ok) {
			/* be sure to assert-crash early if error is missing */
			i_assert(error != NULL);
			if ((ctx->flags & CONFIG_PARSE_FLAG_DELAY_ERRORS) == 0) {
				/* the errors are still slightly delayed so
				   we get the full list of them. */
				error = p_strdup(new_config->pool, error);
				array_push_back(&new_config->errors, &error);
			} else if (p->delayed_error == NULL) {
				/* Settings checking failed, but we're delaying
				   the error until the settings struct is used
				   by the client side. See config-parser.h */
				p->delayed_error = p_strdup(ctx->pool, error);
			}
		}
	}
	pool_unref(&tmp_pool);
	event_unref(&event);
}

static const char *
get_str_setting(struct config_filter_parser *parser, const char *key,
		const char *default_value)
{
	struct config_module_parser *module_parser;
	unsigned int key_idx;

	module_parser = parser->module_parsers;
	for (; module_parser->info != NULL; module_parser++) {
		if (module_parser->change_counters != NULL &&
		    setting_parser_info_find_key(module_parser->info, key,
						 &key_idx) &&
		    module_parser->change_counters[key_idx] != 0) {
			i_assert(module_parser->info->defines[key_idx].type != SET_STRLIST &&
				 module_parser->info->defines[key_idx].type != SET_BOOLLIST &&
				 module_parser->info->defines[key_idx].type != SET_FILTER_ARRAY);
			return set_str_expanded(&module_parser->settings[key_idx]);
		}
	}
	return default_value;
}

static int
config_all_parsers_check(struct config_parser_context *ctx,
			 struct config_parsed *new_config,
			 enum config_parse_flags flags, const char **error_r)
{
	struct config_filter_parser *const *parsers;
	unsigned int i, count;
	const char *ssl_set, *global_ssl_set;
	bool ssl_warned = FALSE;

	if (ctx->cur_section->prev != NULL) {
		*error_r = t_strdup_printf(
			"Missing '}' (section started at %s:%u)",
			ctx->cur_section->open_path,
			ctx->cur_section->open_linenum);
		return -1;
	}

	int fd;
	T_BEGIN {
		fd = config_dump_full(new_config, CONFIG_DUMP_FULL_DEST_TEMPDIR,
				      0, NULL);
	} T_END;
	if (fd == -1) {
		*error_r = "Failed to write binary config file";
		return -1;
	}
	struct settings_root *set_root = settings_root_init();
	const char *const *specific_protocols, *error;
	if (settings_read(set_root, fd, "(temp config file)", NULL, NULL, 0,
			  &specific_protocols, &error) < 0) {
		*error_r = t_strdup_printf(
			"Failed to read settings from binary config file: %s",
			error);
		i_close_fd(&fd);
		settings_root_deinit(&set_root);
		return -1;
	}

	parsers = array_get(&ctx->all_filter_parsers, &count);
	i_assert(parsers[count] == NULL);

	struct event *event = event_create(NULL);
	event_set_ptr(event, SETTINGS_EVENT_ROOT, set_root);

	int ret = 0;
	if (hook_config_parser_end != NULL &&
	    (flags & CONFIG_PARSE_FLAG_EXTERNAL_HOOKS) != 0) {
		/* Assume the hooks want to update default settings */
		struct config_filter_parser *defaults_parser =
			array_idx_elem(&ctx->all_filter_parsers, 1);
		i_assert(config_filter_is_empty_defaults(&defaults_parser->filter));
		ctx->cur_section->filter_parser = defaults_parser;

		ret = hook_config_parser_end(ctx, new_config, event, error_r);
	}

	/* Run check_func()s for each filter independently. If you have
	   protocol imap { ... local { ... } } blocks, it's going to check the
	   "local" filter without applying settings from the "protocol imap"
	   filter. In theory this could complain about nonexistent problems,
	   but currently such checks are rare enough that this shouldn't be a
	   practical problem. Fixing this is possible and it was done in a
	   previous version of the code, but it got in the way of cleaning up
	   the config code, so at least for now it's not done. */
	global_ssl_set = get_str_setting(parsers[0], "ssl", "");
	for (i = 0; i < count && ret == 0; i++) {
		if (parsers[i]->filter.default_settings)
			continue;
		if (parsers[i]->filter.filter_name_array &&
		    config_filter_has_include_group(&parsers[i]->filter))
			continue;
		ssl_set = get_str_setting(parsers[i], "ssl", global_ssl_set);
		if (strcmp(ssl_set, "no") != 0 &&
		    strcmp(global_ssl_set, "no") == 0 && !ssl_warned) {
			i_warning("SSL is disabled because global ssl=no, "
				  "ignoring ssl=%s for subsection", ssl_set);
			ssl_warned = TRUE;
		}

		config_filter_parser_check(ctx, new_config, event, parsers[i]);
	}
	event_unref(&event);
	i_close_fd(&fd);
	settings_root_deinit(&set_root);

	if (ret < 0)
		return -1;
	const char *const *errors =
		array_get(config_parsed_get_errors(new_config), &count);
	if (count > 0) {
		/* Use the first error as the main error. The others are also
		   printed out by doveconf. */
		*error_r = errors[0];
		return -1;
	}
	return 0;
}

static int
str_append_file(struct config_parser_context *ctx, string_t *str,
		const char *key, const char *path, const char **error_r)
{
	unsigned char buf[1024];
	int fd;
	ssize_t ret;

	*error_r = NULL;

	fd = open(path, O_RDONLY);
	if (fd == -1) {
		*error_r = t_strdup_printf("%s: Can't open file %s: %m",
					   key, path);
		return -1;
	}
	if (config_parser_add_seen_file_fd(ctx, fd, path, error_r) < 0) {
		i_close_fd(&fd);
		return -1;
	}
	while ((ret = read(fd, buf, sizeof(buf))) > 0)
		str_append_data(str, buf, ret);
	if (ret < 0) {
		*error_r = t_strdup_printf("%s: read(%s) failed: %m",
					   key, path);
	}
	i_close_fd(&fd);
	return ret < 0 ? -1 : 0;
}

static int settings_add_include(struct config_parser_context *ctx, const char *path,
				bool ignore_errors, const char **error_r)
{
	struct input_stack *tmp, *new_input;
	int fd;

	for (tmp = ctx->cur_input; tmp != NULL; tmp = tmp->prev) {
		if (strcmp(tmp->path, path) == 0)
			break;
	}
	if (tmp != NULL) {
		*error_r = t_strdup_printf("Recursive include file: %s", path);
		return -1;
	}

	if ((fd = open(path, O_RDONLY)) == -1) {
		if (ignore_errors)
			return 0;

		*error_r = t_strdup_printf("Couldn't open include file %s: %m",
					   path);
		return -1;
	}
	if (config_parser_add_seen_file_fd(ctx, fd, path, error_r) < 0) {
		/* We only get here if fstat(fd, &st) failed. As we don't
		 * specify what the issue is, it's safest to close the file via
		 * the descriptor but ignore the result. */
		i_close_fd(&fd);
		return -1;
	}

	new_input = p_new(ctx->pool, struct input_stack, 1);
	new_input->prev = ctx->cur_input;
	new_input->path = p_strdup(ctx->pool, path);
	new_input->input = i_stream_create_fd_autoclose(&fd, SIZE_MAX);
	i_stream_set_return_partial_line(new_input->input, TRUE);
	ctx->cur_input = new_input;
	return 0;
}

static int
settings_include(struct config_parser_context *ctx, const char *pattern,
		 bool ignore_errors)
{
	const char *error;
#ifdef HAVE_GLOB
	glob_t globbers;
	unsigned int i;

	switch (glob(pattern, GLOB_BRACE, NULL, &globbers)) {
	case 0:
		break;
	case GLOB_NOSPACE:
		ctx->error = "glob() failed: Not enough memory";
		return -1;
	case GLOB_ABORTED:
		ctx->error = "glob() failed: Read error";
		return -1;
	case GLOB_NOMATCH:
		if (ignore_errors)
			return 0;
		ctx->error = "No matches";
		return -1;
	default:
		ctx->error = "glob() failed: Unknown error";
		return -1;
	}

	/* iterate through the different files matching the globbing */
	for (i = globbers.gl_pathc; i > 0; i--) {
		if (settings_add_include(ctx, globbers.gl_pathv[i-1],
					 ignore_errors, &error) < 0) {
			ctx->error = p_strdup(ctx->pool, error);
			return -1;
		}
	}
	globfree(&globbers);
	return 0;
#else
	if (settings_add_include(ctx, pattern, ignore_errors, &error) < 0) {
		ctx->error = p_strdup(ctx->pool, error);
		return -1;
	}
	return 0;
#endif
}

static int config_str_unescape(char *str, const char **error_r)
{
	/* @UNSAFE */
	char *dest;

	while (*str != '\\' && *str != '\0')
		str++;

	for (dest = str; *str != '\0'; str++) {
		if (*str == '\\') {
			str++;
			if (*str != '\\' && *str != '"') {
				*error_r = t_strdup_printf(
					"Unknown escape sequence \\%c", *str);
				return -1;
			}
		}

		*dest++ = *str;
	}

	*dest = '\0';
	return 0;
}

static void
config_parse_line(struct config_parser_context *ctx,
		  char *line, string_t *full_line,
		  struct config_line *config_line_r)
{
	char *key;
	size_t len;
	char *p;

	i_zero(config_line_r);

	/* @UNSAFE: line is modified */

	/* skip whitespace */
	while (i_isspace(*line))
		line++;

	/* ignore comments or empty lines */
	if (*line == '#' || *line == '\0') {
		config_line_r->type = CONFIG_LINE_TYPE_SKIP;
		return;
	}

	/* strip away comments. pretty kludgy way really.. */
	for (p = line; *p != '\0'; p++) {
		if (*p == '\'' || *p == '"') {
			char quote = *p;
			for (p++; *p != quote && *p != '\0'; p++) {
				if (*p == '\\' && p[1] != '\0')
					p++;
			}
			if (*p == '\0')
				break;
		} else if (*p == '#') {
			if (!i_isspace(p[-1])) {
				i_warning("Configuration file %s line %u: "
					  "Ambiguous '#' character in line, treating it as comment. "
					  "Add a space before it to remove this warning.",
					  ctx->cur_input->path,
					  ctx->cur_input->linenum);
			}
			*p = '\0';
			break;
		}
	}

	/* remove whitespace from end of line */
	len = strlen(line);
	while (len >= 1) {
		if(!i_isspace(line[len-1]))
			break;
		len--;
	}
	line[len] = '\0';

	if (len >= 1 && line[len-1] == '\\') {
		/* continues in next line */
		len--;
		while (len >= 1) {
			if(!i_isspace(line[len-1]))
				break;
			len--;
		}
		if(len >= 1) {
			str_append_data(full_line, line, len);
			str_append_c(full_line, ' ');
		}
		config_line_r->type = CONFIG_LINE_TYPE_CONTINUE;
		return;
	}
	if (str_len(full_line) > 0) {
		str_append(full_line, line);
		line = str_c_modifiable(full_line);
	}

	/* a) key = value
	   b) section_type [section_name] {
	   c) } */
	key = line;
	if (*key == '"') {
		config_line_r->key_quoted = TRUE;
		key++; line++;
		while (*line != '\0') {
			if (*line == '\\' && line[1] != '\0')
				line += 2;
			else if (*line == '"') {
				*line++ = '\0';
				break;
			} else
				line++;
		}
		if (config_str_unescape(key, &config_line_r->value) < 0) {
			config_line_r->type = CONFIG_LINE_TYPE_ERROR;
			return;
		}
	} else {
		while (!i_isspace(*line) && *line != '\0' && *line != '=')
			line++;
	}
	if (i_isspace(*line)) {
		*line++ = '\0';
		while (i_isspace(*line)) line++;
	}
	config_line_r->key = key;
	config_line_r->value = line;

	if (strcmp(key, "!include") == 0) {
		config_line_r->type = CONFIG_LINE_TYPE_INCLUDE;
		return;
	}
	if (strcmp(key, "!include_try") == 0) {
		config_line_r->type = CONFIG_LINE_TYPE_INCLUDE_TRY;
		return;
	}

	if (*line == '=') {
		/* a) */
		*line++ = '\0';
		while (i_isspace(*line)) line++;

		if (*line == '<') {
			while (i_isspace(line[1])) line++;
			config_line_r->value = line + 1;
			config_line_r->type = CONFIG_LINE_TYPE_KEYFILE;
			return;
		}
		if (*line != '\'' && *line != '"' && strchr(line, '$') != NULL) {
			config_line_r->value = line;
			config_line_r->type = CONFIG_LINE_TYPE_KEYVARIABLE;
			return;
		}

		len = strlen(line);
		if (len > 0 &&
		    ((*line == '"' && line[len-1] == '"') ||
		     (*line == '\'' && line[len-1] == '\''))) {
			line[len-1] = '\0';
			line++;
			if (config_str_unescape(line, &config_line_r->value) < 0) {
				config_line_r->type = CONFIG_LINE_TYPE_ERROR;
				return;
			}
			config_line_r->value_quoted = TRUE;
		}
		config_line_r->value = line;
		config_line_r->type = CONFIG_LINE_TYPE_KEYVALUE;
		return;
	}

	if (strcmp(key, "}") == 0 && *line == '\0') {
		config_line_r->type = CONFIG_LINE_TYPE_SECTION_END;
		return;
	}

	/* b) + errors */
	line[-1] = '\0';

	if (*line == '{') {
		config_line_r->value = "";
		config_line_r->type = CONFIG_LINE_TYPE_SECTION_BEGIN;
	} else if (strcmp(key, "group") == 0) {
		/* group @group name { */
		config_line_r->key = line;
		while (!i_isspace(*line) && *line != '\0')
			line++;
		if (*line == '\0') {
			config_line_r->value = "Expecting group name";
			config_line_r->type = CONFIG_LINE_TYPE_ERROR;
			return;
		}
		*line++ = '\0';
		while (i_isspace(*line))
			line++;

		config_line_r->value = line;
		while (!i_isspace(*line) && *line != '\0')
			line++;
		if (*line == '\0') {
			config_line_r->value = "Expecting '{'";
			config_line_r->type = CONFIG_LINE_TYPE_ERROR;
			return;
		}
		*line++ = '\0';
		while (i_isspace(*line))
			line++;
		if (*line != '{') {
			config_line_r->value = "Expecting '{'";
			config_line_r->type = CONFIG_LINE_TYPE_ERROR;
			return;
		}

		config_line_r->type = CONFIG_LINE_TYPE_GROUP_SECTION_BEGIN;
	} else {
		/* get section name */
		if (*line != '"') {
			config_line_r->value = line;
			while (!i_isspace(*line) && *line != '\0')
				line++;
			if (*line != '\0') {
				*line++ = '\0';
				while (i_isspace(*line))
					line++;
			}
		} else {
			char *value = ++line;
			while (*line != '"' && *line != '\0')
				line++;
			if (*line == '"') {
				*line++ = '\0';
				while (i_isspace(*line))
					line++;
				if (config_str_unescape(value, &config_line_r->value) < 0) {
					config_line_r->type = CONFIG_LINE_TYPE_ERROR;
					return;
				}
				config_line_r->value = value;
				config_line_r->value_quoted = TRUE;
			}
		}
		if (*line != '{') {
			config_line_r->value = "Expecting '{'";
			config_line_r->type = CONFIG_LINE_TYPE_ERROR;
			return;
		}
		config_line_r->type = CONFIG_LINE_TYPE_SECTION_BEGIN;
	}
	if (line[1] != '\0') {
		config_line_r->value = "Garbage after '{'";
		config_line_r->type = CONFIG_LINE_TYPE_ERROR;
	}
}

static struct config_filter_parser *
group_find_name(struct config_include_group_filters *group, const char *name)
{
	struct config_filter_parser *filter;

	array_foreach_elem(&group->filters, filter) {
		const char *filter_name =
			i_strchr_to_next(filter->filter.filter_name, '/');
		i_assert(filter_name != NULL);
		if (strcmp(filter_name, name) == 0)
			return filter;
	}
	return NULL;
}

static void
config_module_parsers_merge(pool_t pool, struct config_module_parser *dest,
			    const struct config_module_parser *src,
			    bool overwrite, unsigned int new_change_counter)
{
	for (; dest->info != NULL; dest++, src++) {
		i_assert(dest->info == src->info);
		if (dest->set_count == 0) {
			/* destination is empty - just copy the whole src */
			*dest = *src;
			if (new_change_counter != 0 && src->set_count > 0) {
				dest->settings =
					p_new(pool, union config_module_parser_setting,
					      dest->set_count);
				dest->change_counters =
					p_new(pool, uint8_t, dest->set_count);
				for (unsigned int i = 0; i < dest->set_count; i++) {
					if (src->change_counters[i] != 0) {
						dest->settings[i] =
							src->settings[i];
						dest->change_counters[i] =
							new_change_counter;
					}
				}
			}
			continue;
		}
		if (src->set_count == 0) {
			/* source is empty - nothing to do */
			continue;
		}
		i_assert(dest->set_count == src->set_count);

		if (dest->delayed_error != NULL) {
			/* already failed */
			continue;
		}
		if (src->delayed_error != NULL) {
			/* copy the failure */
			dest->delayed_error = src->delayed_error;
			continue;
		}

		/* copy settings that have changed in source, but not in dest */
		for (unsigned int i = 0; i < src->set_count; i++) {
			if (src->change_counters[i] != 0 &&
			    (dest->change_counters[i] == 0 || overwrite)) {
				dest->settings[i] = src->settings[i];
				dest->change_counters[i] =
					new_change_counter != 0 ?
					new_change_counter :
					src->change_counters[i];
			}
		}
	}
	i_assert(src->info == NULL);
}

static void
config_filters_merge_tree(struct config_parser_context *ctx,
			  struct config_filter_parser *dest_parent,
			  struct config_filter_parser *src_parent,
			  bool drop_merged, bool overwrite,
			  unsigned int new_change_counter)
{
	struct config_filter_parser *src;
	struct config_filter_parser *dest;

	i_assert(array_is_empty(&src_parent->include_groups));
	for (src = src_parent->children_head; src != NULL; src = src->next) {
		dest = config_filters_find_child(dest_parent, &src->filter);
		if (dest == NULL) {
			dest = config_add_new_parser(ctx, &src->filter,
						     dest_parent);
			dest->filter_required_setting_seen =
				src->filter_required_setting_seen;
		}
		if (drop_merged)
			src->dropped = TRUE;
		config_module_parsers_merge(ctx->pool, dest->module_parsers,
					    src->module_parsers, overwrite,
					    new_change_counter);
		config_filters_merge_tree(ctx, dest, src,
					  drop_merged, overwrite,
					  new_change_counter);
	}
}

static void config_filters_merge(struct config_parser_context *ctx,
				 struct config_parsed *config,
				 struct config_filter_parser *dest_filter,
				 struct config_filter_parser *src_filter,
				 bool drop_merged, bool overwrite,
				 unsigned int new_change_counter)
{
	i_assert(array_is_empty(&src_filter->include_groups));

	if (drop_merged)
		src_filter->dropped = TRUE;
	config_module_parsers_merge(ctx->pool, dest_filter->module_parsers,
				    src_filter->module_parsers, overwrite,
				    new_change_counter);
	config_filters_merge_tree(ctx, dest_filter, src_filter,
				  drop_merged, overwrite, new_change_counter);

	array_append_zero(&ctx->all_filter_parsers);
	array_pop_back(&ctx->all_filter_parsers);
	if (config != NULL)
		config->filter_parsers = array_front(&ctx->all_filter_parsers);
}

static void
config_parse_merge_filters(struct config_parser_context *ctx,
			   struct config_parsed *config,
			   const struct config_filter *dump_filter)
{
	for (unsigned int i = 2; config->filter_parsers[i] != NULL; i++) {
		struct config_filter_parser *filter = config->filter_parsers[i];

		int ret = config_filter_match_no_recurse(&filter->filter,
							 dump_filter);
		if (ret < 0 || filter->filter.filter_name != NULL) {
			/* Incomplete filter */
			continue;
		}
		if (ret == 0) {
			/* Filter mismatch */
			filter->dropped = TRUE;
			continue;
		}

		config_filters_merge(ctx, config, filter->parent, filter,
				     TRUE, TRUE, 0);
	}
}

static void
config_parse_merge_default_filters(struct config_parser_context *ctx,
				   struct config_parsed *config)
{
	struct config_filter_parser *root_parser, *defaults_parser;

	root_parser = array_idx_elem(&ctx->all_filter_parsers, 0);
	defaults_parser = array_idx_elem(&ctx->all_filter_parsers, 1);
	i_assert(config_filter_is_empty_defaults(&defaults_parser->filter));

	config_filters_merge(ctx, config, root_parser, defaults_parser,
			     FALSE, FALSE, 0);
}

static int config_parser_filter_cmp(struct config_filter_parser *const *f1,
				    struct config_filter_parser *const *f2)
{
	/* Preserve position for the first two parsers */
	if ((*f1)->create_order <= 1) {
		if ((*f2)->create_order <= 1)
			return (int)(*f1)->create_order - (int)(*f2)->create_order;
		return -1;
	}
	if ((*f2)->create_order <= 1)
		return 1;

	/* Next, order by the number of named list filters, so more specific
	   filters are applied before less specific ones. (Applying is done in
	   reverse order from the last filter to the first.)

	   Don't include other types of filters in this check, since e.g.
	   hierarchical named filters may commonly be used to specify defaults
	   (e.g. layout_fs { sdbox { } }) which shouldn't override even a
	   smaller number of named list filters (e.g. mailbox foo { .. }). */
	int ret = (int)(*f1)->named_list_filter_count -
		(int)(*f2)->named_list_filter_count;
	if (ret != 0)
		return ret;

	/* After sorting by named list filter hierarchy count, sort by
	   named non-list filter hierarchy count. */
	ret = (int)(*f1)->named_filter_count - (int)(*f2)->named_filter_count;
	if (ret != 0)
		return ret;

	/* Finally, just order them in the order of creation. */
	return (int)(*f1)->create_order - (int)(*f2)->create_order;
}

static int config_expand_value(struct config_parser_context *ctx,
			       struct config_filter_parser *filter_parser,
			       const char *key, const char **value)
{
	if ((*value)[0] == CONFIG_VALUE_PREFIX_EXPANDED)
		return 0;
	i_assert((*value)[0] == CONFIG_VALUE_PREFIX_SET_UNEXPANDED);

	string_t *new_value = t_str_new(128);
	if (config_write_keyvariable(ctx, filter_parser, key,
				     *value + 1, new_value, FALSE) < 0) {
		/* We mostly checked the validity of the value. If we're here,
		   it should be because the settings expansion went into
		   recursive loop. */
		return -1;
	}
	*value = p_strdup(ctx->pool, str_c(new_value));
	return 0;
}

static int
config_module_parser_expand_values(struct config_parser_context *ctx,
				   struct config_filter_parser *filter_parser,
				   const struct config_module_parser *p)
{
	if (p->change_counters == NULL)
		return 0;

	for (unsigned int i = 0; p->info->defines[i].key != NULL; i++) {
		if (p->change_counters[i] == 0)
			continue;

		union config_module_parser_setting *set = &p->settings[i];
		switch (p->info->defines[i].type) {
		case SET_STRLIST:
		case SET_BOOLLIST: {
			if (set->list.prefixed_values == NULL)
				break;
			unsigned int j, count;
			const char **prefixed_strings =
				array_get_modifiable(set->list.prefixed_values, &count);
			for (j = 0; j < count; j += 2) {
				if (config_expand_value(ctx, filter_parser,
							p->info->defines[i].key,
							&prefixed_strings[j]) < 0 ||
				    config_expand_value(ctx, filter_parser,
							p->info->defines[i].key,
							&prefixed_strings[j + 1]) < 0)
					return -1;
			}
			break;
		}
		case SET_FILTER_ARRAY:
		case SET_FILE:
			break;
		default:
			if (config_expand_value(ctx, filter_parser,
						p->info->defines[i].key,
						&set->prefixed_str) < 0)
				return -1;
			break;
		}
	}
	return 0;
}

static int
config_filter_parser_expand_values(struct config_parser_context *ctx,
				   struct config_filter_parser *filter_parser)
{
	const struct config_module_parser *l = filter_parser->module_parsers;
	for (unsigned int info_idx = 0; l[info_idx].info != NULL; info_idx++) {
		if (config_module_parser_expand_values(ctx, filter_parser,
						       &l[info_idx]) < 0)
			return -1;
	}
	return 0;
}

static int config_parse_expand_values(struct config_parser_context *ctx)
{
	struct config_filter_parser *filter_parser;

	array_foreach_elem(&ctx->all_filter_parsers, filter_parser) {
		if (config_filter_parser_expand_values(ctx, filter_parser) < 0)
			return -1;
	}
	return 0;
}

static int
config_parse_finish(struct config_parser_context *ctx,
		    enum config_parse_flags flags,
		    const struct config_filter *dump_filter,
		    struct config_parsed **config_r, const char **error_r)
{
	struct config_parsed *new_config;
	const char *error;
	int ret = 0;

	if (config_parse_expand_values(ctx) < 0) {
		*error_r = t_strdup(ctx->error);
		return -1;
	}

	new_config = p_new(ctx->pool, struct config_parsed, 1);
	new_config->pool = ctx->pool;
	pool_ref(new_config->pool);
	new_config->dovecot_config_version = ctx->dovecot_config_version;
	p_array_init(&new_config->errors, ctx->pool, 1);
	new_config->seen_paths = ctx->seen_paths;

	array_sort(&ctx->all_filter_parsers, config_parser_filter_cmp);
	array_append_zero(&ctx->all_filter_parsers);
	array_pop_back(&ctx->all_filter_parsers);
	new_config->filter_parsers = array_front(&ctx->all_filter_parsers);
	new_config->module_parsers = ctx->root_module_parsers;

	new_config->include_groups = ctx->all_include_groups;
	i_zero(&ctx->all_include_groups);

	/* Copy the all_keys to new_config, which takes care of freeing it.
	   It's temporarily needed to exist in both ctx and new_config. */
	new_config->all_keys = ctx->all_keys;

	/* Destroy it here, so config filter tree merging no longer attempts
	   to update it. */
	hash_table_destroy(&ctx->all_filter_parsers_hash);

	if (ret == 0 && dump_filter != NULL)
		config_parse_merge_filters(ctx, new_config, dump_filter);

	if (ret < 0)
		;
	else if ((ret = config_all_parsers_check(ctx, new_config, flags, &error)) < 0) {
		*error_r = t_strdup_printf("Error in configuration file %s: %s",
					   ctx->path, error);
	}

	i_zero(&ctx->all_keys);

	/* Merge defaults into main settings after running settings checks. */
	if (ret == 0 && (flags & CONFIG_PARSE_FLAG_MERGE_DEFAULT_FILTERS) != 0)
		config_parse_merge_default_filters(ctx, new_config);

	if (ret < 0 && (flags & CONFIG_PARSE_FLAG_RETURN_BROKEN_CONFIG) == 0) {
		config_parsed_free(&new_config);
		return -1;
	}
	*config_r = new_config;
	return ret;
}

static int config_write_keyvariable(struct config_parser_context *ctx,
				    struct config_filter_parser *filter_parser,
				    const char *key, const char *value,
				    string_t *prefixed_str,
				    bool delay_set_expand)
{
	const char *var_end, *orig_value = value;
	bool force_expand = FALSE;
	bool seen_settings = FALSE;
	int ret = 0;

	if (!array_is_created(&ctx->var_chain_keys))
		p_array_init(&ctx->var_chain_keys, ctx->pool, 4);
	else if (array_lsearch(&ctx->var_chain_keys, &key, i_strcmp_p) != NULL) {
		ctx->error = p_strdup_printf(ctx->pool,
			"Chained $SET:%s loops back to itself", key);
		return -1;
	}
	array_push_back(&ctx->var_chain_keys, &key);

	str_append_c(prefixed_str, CONFIG_VALUE_PREFIX_EXPANDED);
	while (value != NULL) {
		const char *var_name, *env_name, *set_name;
		bool var_is_set, expand_values = ctx->expand_values;
		var_end = strchr(value, ' ');

		if (var_end == NULL)
			var_name = value;
		else
			var_name = t_strdup_until(value, var_end);
		var_is_set = str_begins(var_name, "$SET:", &set_name);
		/* Always expand values when value refers to the variable itself, e.g.:

		   login_greeting = Hello
		   login_greeting = $SET:login_greeting world

		   Always show this as "Hello world" output in doveconf (i.e.
		   also when ctx->expand_values=FALSE). If we didn't expand it,
		   it would be visible only as "$SET:login_greeting world",
		   hiding the "Hello" string entirely. */
		if (var_is_set) {
			seen_settings = TRUE;
			if (strcmp(key, set_name) == 0) {
				expand_values = TRUE;
				force_expand = TRUE;
			}
		}

		if (expand_values &&
		    str_begins(var_name, "$ENV:", &env_name)) {
			/* use environment variable */
			const char *envval = getenv(env_name);
			if (envval != NULL)
				str_append(prefixed_str, envval);
		} else if (expand_values && var_is_set) {
			static struct config_filter_parser *set_parser;
			struct config_parser_key *config_key;
			const char *full_set_name = set_name;

			set_name = strrchr(full_set_name, '/');
			if (set_name == NULL) {
				/* Get setting from the current filter */
				set_name = full_set_name;
				set_parser = filter_parser;
			} else {
				/* Getting setting from the specified filter
				   path. The path is expected to start from
				   root. For example:
				   $SET:service/auth/service_client_limit
				   Note that auto-prefixing isn't currently
				   supported. */
				const char *filter_path = t_strdup_until(
					full_set_name, set_name);
				set_parser = config_filter_parser_find_path(ctx,
					filter_path);
				set_name++;

				if (set_parser == NULL) {
					ctx->error = p_strdup_printf(ctx->pool,
						"Failed to expand $SET:%s: "
						"Unknown filter path: %s",
						full_set_name, filter_path);
					ret = -1;
					break;
				}
			}
			config_key = hash_table_lookup(ctx->all_keys, set_name);
			if (config_key == NULL) {
				ctx->error = p_strdup_printf(ctx->pool,
					"Failed to expand $SET:%s: "
					"Unknown setting: %s",
					full_set_name, set_name);
				ret = -1;
				break;
			}
			ret = config_get_value(ctx, set_parser,
					       config_key, full_set_name,
					       prefixed_str);
			if (ret == 0) {
				ctx->error = p_strdup_printf(ctx->pool,
					"Failed to expand $SET:%s: "
					"Setting type can't be expanded to string",
					full_set_name);
				ret = -1;
			}
			if (ret < 0)
				break;
			ret = 0;
		} else {
			str_append(prefixed_str, var_name);
		}

		if (var_end == NULL)
			break;

		str_append_c(prefixed_str, ' ');

		/* find next token */
		while (*var_end != '\0' && i_isspace(*var_end)) var_end++;
		value = var_end;
		while (*var_end != '\0' && !i_isspace(*var_end)) var_end++;
	}

	if (ret == 0 && delay_set_expand && seen_settings && !force_expand) {
		/* Delay expanding $SET until the config is parsed. However,
		   the setting names were validated above, so the final
		   expansion shouldn't fail. */
		str_truncate(prefixed_str, 0);
		str_append_c(prefixed_str,
			     CONFIG_VALUE_PREFIX_SET_UNEXPANDED);
		str_append(prefixed_str, orig_value);
	}
	array_pop_back(&ctx->var_chain_keys);
	return ret;
}

static int config_write_value(struct config_parser_context *ctx,
			      const struct config_line *line)
{
	const char *error, *path, *key_with_path;

	str_truncate(ctx->prefixed_value, 0);

	switch (line->type) {
	case CONFIG_LINE_TYPE_KEYVALUE:
		str_append_c(ctx->prefixed_value, CONFIG_VALUE_PREFIX_EXPANDED);
		str_append(ctx->prefixed_value, line->value);
		break;
	case CONFIG_LINE_TYPE_KEYFILE:
		str_append_c(ctx->prefixed_value, CONFIG_VALUE_PREFIX_EXPANDED);
		if (!ctx->expand_values) {
			str_append_c(ctx->prefixed_value, '<');
			str_append(ctx->prefixed_value, line->value);
		} else {
			key_with_path =
				config_section_is_in_list(ctx->cur_section) ?
				t_strdup_printf("%s"SETTINGS_SEPARATOR_S"%s",
						ctx->cur_section->key,
						line->key) :
				line->key;
			path = fix_relative_path(line->value, ctx->cur_input);
			if (str_append_file(ctx, ctx->prefixed_value,
					    key_with_path, path, &error) < 0) {
				/* file reading failed */
				ctx->error = p_strdup(ctx->pool, error);
				return -1;
			}
		}
		break;
	case CONFIG_LINE_TYPE_KEYVARIABLE:
		if (config_write_keyvariable(ctx, ctx->cur_section->filter_parser,
					     line->key, line->value,
					     ctx->prefixed_value, TRUE) < 0)
			return -1;
		break;
	default:
		i_unreached();
	}
	return 0;
}

static bool
config_section_has_non_named_list_filters(struct config_section_stack *section)
{
	struct config_filter *filter = &section->filter_parser->filter;

	do {
		if (filter->protocol != NULL ||
		    filter->local_name != NULL ||
		    filter->local_host != NULL ||
		    filter->remote_host != NULL ||
		    filter->local_bits > 0 ||
		    filter->remote_bits > 0 ||
		    (filter->filter_name != NULL && !filter->filter_name_array))
			return TRUE;

		filter = filter->parent;
	} while (filter != NULL);
	return FALSE;
}

static void
config_parser_check_warnings(struct config_parser_context *ctx, const char *key,
			     bool root_setting)
{
	const char *path, *first_pos;

	if (ctx->cur_input == NULL) {
		/* coming from old_settings_handle_post() - we don't need to
		   track seen settings in there. */
		return;
	}
	if (ctx->change_counter == CONFIG_PARSER_CHANGE_DEFAULTS) {
		/* Parsing internal settings. Especially settings in
		   config_import shouldn't be tracked. */
		return;
	}

	first_pos = hash_table_lookup(ctx->seen_settings, key);
	if (root_setting) {
		/* changing a root setting. if we've already seen it inside
		   filters, log a warning. */
		if (first_pos == NULL)
			return;
		i_warning("%s line %u: Global setting %s won't change the setting inside an earlier filter at %s "
			  "(if this is intentional, avoid this warning by moving the global setting before %s)",
			  ctx->cur_input->path, ctx->cur_input->linenum,
			  key, first_pos, first_pos);
		return;
	}
	if (first_pos != NULL)
		return;
	if (!config_section_has_non_named_list_filters(ctx->cur_section)) {
		/* Ignore all settings inside sections containing only named
		   list filters. They aren't globals, and we don't want
		   warnings about overriding them if there's a same global
		   setting later on. It just complicates configs in tests. */
		return;
	}
	first_pos = p_strdup_printf(ctx->pool, "%s line %u",
				    ctx->cur_input->path, ctx->cur_input->linenum);
	path = p_strdup(ctx->pool, key);
	hash_table_insert(ctx->seen_settings, path, first_pos);
}

static bool config_version_find(const char *version, const char **error_r)
{
	const char *const supported_versions[] = {
#ifdef DOVECOT_PRO_EDITION
		"3.1.0",
#else
		"2.4.0",
		"2.4.1",
#endif
		NULL
	};
	/* FIXME: implement full version checking later */
	if (!str_array_find(supported_versions, version) &&
	    strcmp(DOVECOT_CONFIG_VERSION, version) != 0) {
		*error_r = t_strdup_printf(
			"Currently supported versions are: %s%s",
			t_strarray_join(supported_versions, " "),
			str_array_find(supported_versions,
				       DOVECOT_CONFIG_VERSION) ? "" :
			t_strdup_printf(" %s", DOVECOT_CONFIG_VERSION));
		return FALSE;
	}
	return TRUE;
}

static bool
dovecot_config_version_equals(struct config_parser_context *ctx, const char *value)
{
	if (strcmp(ctx->dovecot_config_version, value) == 0)
		return TRUE;
	if (strcmp(ctx->dovecot_config_version, CONFIG_VERSION_MAX) == 0 &&
	    strcmp(value, CONFIG_VERSION_GIT) == 0)
		return TRUE;
	return FALSE;
}

static bool config_parser_get_version(struct config_parser_context *ctx,
				      const struct config_line *line)
{
	const char *error;

	if (line->type == CONFIG_LINE_TYPE_CONTINUE ||
	    line->type == CONFIG_LINE_TYPE_SKIP ||
	    line->type == CONFIG_LINE_TYPE_ERROR)
		return FALSE;

	if (strcmp(line->key, "dovecot_config_version") == 0) {
		if (ctx->dovecot_config_version == NULL)
			;
		else if (!dovecot_config_version_equals(ctx, line->value)) {
			ctx->error = "dovecot_config_version value can't be changed once set";
			return TRUE;
		} else {
			/* Same value, ignore. This is mainly helpful to allow
			   config files to include other config files in
			   testing. */
			return TRUE;
		}
	} else {
		if (ctx->dovecot_config_version == NULL)
			ctx->error = "The first setting must be dovecot_config_version";
		return FALSE;
	}

	if (line->type != CONFIG_LINE_TYPE_KEYVALUE)
		ctx->error = "Invalid dovecot_config_version: value is not a string";
	else if (!config_version_find(line->value, &error)) {
		ctx->error = p_strdup_printf(ctx->pool,
			"Invalid dovecot_config_version: %s", error);
	} else if (strcmp(line->value, CONFIG_VERSION_GIT) == 0) {
		/* git build - this is the same as the latest version. */
		ctx->dovecot_config_version = CONFIG_VERSION_MAX;
	} else {
		ctx->dovecot_config_version = p_strdup(ctx->pool, line->value);
	}
	return TRUE;
}

static struct config_filter_parser *
config_filter_parser_replace_parent(pool_t pool,
				    const struct config_filter_parser *src,
				    struct config_filter_parser *parent)
{
	struct config_filter_parser **p, *dest =
		p_new(pool, struct config_filter_parser, 1);
	*dest = *src;
	dest->parent = parent;
	dest->filter.parent = parent == NULL ? NULL : &parent->filter;

	/* Fix the parent pointer in children also */
	for (p = &dest->children_head; *p != NULL; p = &(*p)->next) {
		*p = config_filter_parser_replace_parent(pool, *p, dest);
		dest->children_tail = *p;
	}
	return dest;
}

static int
config_parser_include_merge(struct config_parser_context *ctx,
			    const struct config_include_group *include_group,
			    const char **error_r)
{
	struct config_include_group_filters *group =
		hash_table_lookup(ctx->all_include_groups,
				  include_group->label);
	if (group == NULL) {
		*error_r = t_strdup_printf("Unknown group label @%s",
					   include_group->label);
		return -1;
	}

	struct config_filter_parser *include_filter =
		group_find_name(group, include_group->name);
	if (include_filter == NULL) {
		*error_r = t_strdup_printf("Unknown group @%s=%s",
			include_group->label, include_group->name);
		return -1;
	}

	config_module_parsers_merge(ctx->pool,
		ctx->cur_section->filter_parser->module_parsers,
		include_filter->module_parsers, FALSE,
		CONFIG_PARSER_CHANGE_GROUP);

	struct config_filter_parser *src_filter = include_filter->children_head;
	for (; src_filter != NULL; src_filter = src_filter->next) {
		/* replace @group parent with the current section */
		struct config_filter_parser *dest, *new_src_filter =
			config_filter_parser_replace_parent(ctx->pool,
				src_filter, ctx->cur_section->filter_parser);
		/* If parent filter now has a reverse default_settings,
		   use the parent with the matching default_settings. */
		struct config_filter_parser *parent_parser =
			ctx->cur_section->filter_parser;
		if (parent_parser->filter.default_settings != new_src_filter->filter.default_settings) {
			config_parse_fill_reverse_default_siblings(ctx);
			parent_parser = parent_parser->reverse_default_sibling;
		}

		dest = config_filters_find_child(parent_parser,
						 &new_src_filter->filter);
		if (dest == NULL) {
			dest = config_add_new_parser(ctx, &new_src_filter->filter,
						     parent_parser);
			dest->filter_required_setting_seen =
				new_src_filter->filter_required_setting_seen;
		}
		config_filters_merge(ctx, NULL, dest, new_src_filter,
				     FALSE, FALSE, CONFIG_PARSER_CHANGE_GROUP);
	}
	return 0;
}

static void
config_parser_include_add_or_update(struct config_parser_context *ctx,
				    const char *group, const char *name)
{
	struct config_filter_parser *filter_parser =
		ctx->cur_section->filter_parser;
	struct config_include_group *include_group = NULL;
	const char *error;
	bool found = FALSE;

	if (!array_is_created(&filter_parser->include_groups))
		p_array_init(&filter_parser->include_groups, ctx->pool, 4);
	array_foreach_modifiable(&filter_parser->include_groups, include_group) {
		if (strcmp(include_group->label, group) == 0) {
			/* preserve original position */
			found = TRUE;
			break;
		}
	}
	if (!found) {
		include_group = array_append_space(&filter_parser->include_groups);
		include_group->label = p_strdup(ctx->pool, group);
	}
	include_group->name = p_strdup(ctx->pool, name);
	include_group->last_path =
		p_strdup(ctx->pool, ctx->cur_input->path);
	include_group->last_linenum = ctx->cur_input->linenum;

	if (config_parser_include_merge(ctx, include_group, &error) < 0)
		ctx->error = p_strdup(ctx->pool, error);
}

void config_parser_apply_line(struct config_parser_context *ctx,
			      const struct config_line *line)
{
	const char *full_key;
	bool root_setting;

	switch (line->type) {
	case CONFIG_LINE_TYPE_SKIP:
		break;
	case CONFIG_LINE_TYPE_CONTINUE:
		i_unreached();
	case CONFIG_LINE_TYPE_ERROR:
		ctx->error = p_strdup(ctx->pool, line->value);
		break;
	case CONFIG_LINE_TYPE_KEYVALUE:
	case CONFIG_LINE_TYPE_KEYFILE:
	case CONFIG_LINE_TYPE_KEYVARIABLE:
		if (config_write_value(ctx, line) < 0) {
			if (config_apply_error(ctx, line->key) < 0)
				break;
		} else if (line->key[0] == SETTINGS_INCLUDE_GROUP_PREFIX &&
			   !line->key_quoted) {
			if (config_filter_has_include_group(&ctx->cur_section->filter_parser->filter)) {
				ctx->error = "Recursive include groups not allowed";
				break;
			}
			if (str_c(ctx->prefixed_value)[0] != CONFIG_VALUE_PREFIX_EXPANDED) {
				ctx->error = "Include groups cannot contain $variables";
				break;
			}
			config_parser_include_add_or_update(ctx, line->key + 1,
				str_c(ctx->prefixed_value) + 1);
		} else {
			/* Either a global key or list/key */
			const char *key_with_path =
				config_section_is_in_list(ctx->cur_section) ?
				t_strdup_printf("%s"SETTINGS_SEPARATOR_S"%s",
						ctx->cur_section->key,
						line->key) :
				line->key;
			if (config_apply_line_full(ctx, line, key_with_path,
						   str_c(ctx->prefixed_value),
						   &full_key,
						   TRUE, &root_setting) < 0) {
				ctx->error = p_strdup_printf(ctx->pool,
					"%s: %s", line->key, ctx->error);
			} else {
				config_parser_check_warnings(ctx, full_key,
							     root_setting);
			}
		}
		break;
	case CONFIG_LINE_TYPE_GROUP_SECTION_BEGIN:
		ctx->cur_section = config_add_new_section(ctx);
		ctx->cur_section->key = "group";

		(void)config_filter_add_new_filter(ctx, line->key, line->value,
						   FALSE);
		break;
	case CONFIG_LINE_TYPE_SECTION_BEGIN: {
		/* See if we need to prefix the key with filter name */
		const struct config_filter *cur_filter =
			&ctx->cur_section->filter_parser->filter;
		const char *key = line->key;
		string_t *attempts = NULL;
		if (cur_filter->filter_name != NULL) {
			const char *filter_key =
				t_str_replace(cur_filter->filter_name, '/', '_');
			const char *key2 = t_strdup_printf("%s_%s",
							   filter_key, key);
			attempts = t_str_new(64);
			if (config_key_can_autoprefix(ctx, key2))
				key = key2;
			else {
				str_printfa(attempts, " (%s", key2);
				filter_key = t_strcut(cur_filter->filter_name, '/');
				key2 = t_strdup_printf("%s_%s", filter_key, key);
				if (config_key_can_autoprefix(ctx, key2))
					key = key2;
				else
					str_printfa(attempts, ", %s", key2);
			}
		} else {
			i_assert(!cur_filter->filter_name_array);
		}

		ctx->cur_section = config_add_new_section(ctx);
		ctx->cur_section->key = p_strdup(ctx->pool, key);

		if (config_filter_add_new_filter(ctx, key, line->value,
						 line->value_quoted) ||
		    ctx->error != NULL) {
			/* new filter or error */
			break;
		}
		if (hash_table_lookup(ctx->all_keys, key) == NULL) {
			if ((ctx->flags & CONFIG_PARSE_FLAG_IGNORE_UNKNOWN) != 0)
				break;
			if (attempts != NULL)
				str_append(attempts, " not found either.)");
			ctx->error = p_strdup_printf(ctx->pool,
				"Unknown section name: %s%s", key,
				attempts == NULL ? "" : str_c(attempts));
			break;
		}

		/* This is SET_STRLIST or SET_BOOLLIST */
		break;
	}
	case CONFIG_LINE_TYPE_SECTION_END:
		if (ctx->cur_section->prev == NULL)
			ctx->error = "Unexpected '}'";
		else if (ctx->cur_section->filter_def != NULL &&
			 ctx->cur_section->filter_def->required_setting != NULL &&
			 !ctx->cur_section->filter_parser->filter_required_setting_seen) {
			ctx->error = p_strdup_printf(ctx->pool,
				"Named filter %s is required to have %s setting, "
				"but it is missing",
				ctx->cur_section->filter_def->key,
				ctx->cur_section->filter_def->required_setting);
		} else {
			ctx->cur_section = ctx->cur_section->prev;
		}
		break;
	case CONFIG_LINE_TYPE_INCLUDE:
	case CONFIG_LINE_TYPE_INCLUDE_TRY:
		(void)settings_include(ctx, fix_relative_path(line->value, ctx->cur_input),
				       line->type == CONFIG_LINE_TYPE_INCLUDE_TRY);
		break;
	}
}

static void
config_parser_add_info(struct config_parser_context *ctx,
		       unsigned int info_idx)
{
	const struct setting_parser_info *info = all_infos[info_idx];
	struct config_parser_key *config_key, *old_config_key;
	const char *name;
	unsigned int i = 0;

	for (i = 0; info->defines[i].key != NULL; i++) {
		const struct setting_define *def = &info->defines[i];

		if ((info->defines[i].flags & SET_FLAG_EOL) != 0) {
			i_panic("struct %s key %s contains SET_FLAG_EOL",
				info->name, def->key);
		}

		i_assert((def->flags & SET_FLAG_EOL) == 0);
		if (def->type == SET_STR ||
		    def->type == SET_STR_NOVARS ||
		    def->type == SET_ENUM) {
			const char *const *valuep =
				CONST_PTR_OFFSET(info->defaults, def->offset);
			if (*valuep == NULL) {
				i_panic("struct %s setting %s default is NULL",
					info->name, def->key);
			}
		}
		if (!hash_table_lookup_full(ctx->all_keys, info->defines[i].key,
					    &name, &old_config_key))
			old_config_key = NULL;
		else {
			const struct setting_parser_info *old_info =
				all_infos[old_config_key->info_idx];
			const struct setting_define *old_def =
				&old_info->defines[old_config_key->define_idx];
			i_assert(strcmp(old_def->key, def->key) == 0);
			if (old_def->type != def->type)
				i_panic("Setting key '%s' type mismatch between infos %s and %s (%d != %d)",
					def->key, old_info->name, info->name,
					old_def->type, def->type);
			if (old_def->flags != def->flags)
				i_panic("Setting key '%s' flags mismatch between infos %s and %s (%d != %d)",
					def->key, old_info->name, info->name,
					old_def->flags, def->flags);
		}
		config_key = p_new(ctx->pool, struct config_parser_key, 1);
		config_key->info_idx = info_idx;
		config_key->define_idx = i;
		if (old_config_key != NULL)
			DLLIST_PREPEND(&old_config_key, config_key);
		hash_table_update(ctx->all_keys, def->key, config_key);
	}
	if ((info->defines[i].flags & SET_FLAG_EOL) == 0) {
		i_panic("struct %s is missing SETTING_DEFINE_LIST_END",
			info->name);
	}
}

static void
config_parser_get_filter_name_prefixes(struct config_parser_context *ctx)
{
	/* Get a sorted list of all (non-list) filter names with '_' appended
	   to them. The settings matching these prefixes will be listed inside
	   the filters. */
	ARRAY_TYPE(const_string) filter_name_prefixes;
	p_array_init(&filter_name_prefixes, ctx->pool, 64);
	for (unsigned int i = 0; ctx->root_module_parsers[i].info != NULL; i++) {
		const struct setting_parser_info *info =
			ctx->root_module_parsers[i].info;
		for (unsigned int j = 0; info->defines[j].key != NULL; j++) {
			if (info->defines[j].type == SET_FILTER_NAME) {
				const char *prefix = p_strconcat(ctx->pool,
					info->defines[j].key, "_", NULL);
				array_push_back(&filter_name_prefixes, &prefix);
			}
		}
	}
	array_sort(&filter_name_prefixes, i_strcmp_p);
	ctx->filter_name_prefixes_count = array_count(&filter_name_prefixes);
	if (ctx->filter_name_prefixes_count > 0)
		ctx->filter_name_prefixes = array_front(&filter_name_prefixes);
}

static int
config_filters_cmp(const struct config_filter *f1,
		   const struct config_filter *f2)
{
	return config_filters_equal(f1, f2) ? 0 : 1;
}

static const char *
config_file_get_input_error(const struct config_parser_context *ctx)
{
	return t_strdup_printf("Error in configuration file %s line %d: %s",
			       ctx->cur_input->path, ctx->cur_input->linenum,
			       ctx->error);
}

int config_parse_file(const char *path, enum config_parse_flags flags,
		      const struct config_filter *dump_filter,
		      struct config_parsed **config_r,
		      const char **error_r)
{
	struct input_stack root, internal;
	struct config_parser_context ctx;
	unsigned int i, count;
	string_t *full_line;
	char *line;
	int fd, ret = 0;
	bool dump_defaults = (path == NULL);

	*config_r = NULL;

	if (path == NULL) {
		path = "<defaults>";
		fd = -1;
	} else {
		fd = open(path, O_RDONLY);
		if (fd < 0) {
			*error_r = t_strdup_printf("open(%s) failed: %m", path);
			return 0;
		}
	}

	i_zero(&ctx);
	ctx.pool = pool_alloconly_create(MEMPOOL_GROWING"config file parser", 1024*256);
	ctx.path = path;
	ctx.dump_defaults = dump_defaults;
	ctx.flags = flags;
	hash_table_create(&ctx.all_keys, ctx.pool, 500, str_hash, strcmp);
	p_array_init(&ctx.seen_paths, ctx.pool, 8);
	if (fd != -1) {
		if (config_parser_add_seen_file_fd(&ctx, fd, path, error_r) < 0)
			return -1;
	} else {
		/* stat contents don't matter for defaults, as long as they
		   don't change. */
		struct stat st;
		i_zero(&st);
		config_parser_add_seen_file(&ctx, &st,
			MASTER_SERVICE_BINARY_CONFIG_DEFAULTS);
	}

	for (count = 0; all_infos[count] != NULL; count++) ;
	config_parser_set_change_counter(&ctx, CONFIG_PARSER_CHANGE_DEFAULTS);
	ctx.root_module_parsers =
		p_new(ctx.pool, struct config_module_parser, count+1);
	unsigned int service_info_idx = UINT_MAX;
	for (i = 0; i < count; i++) {
		if (strcmp(all_infos[i]->name, "service") == 0)
			service_info_idx = i;
		ctx.root_module_parsers[i].info = all_infos[i];
		config_module_parser_init(&ctx, &ctx.root_module_parsers[i]);
		config_parser_add_info(&ctx, i);
		for (unsigned int j = 0; j < i; j++) {
			if (strcmp(all_infos[j]->name, all_infos[i]->name) == 0) {
				/* Just fatal - it's difficult to continue
				   correctly here, and it's not supposed to
				   happen. */
				i_panic("Duplicate settings struct name: %s",
					all_infos[i]->name);
			}
		}
	}
	i_assert(service_info_idx != UINT_MAX ||
		 (flags & CONFIG_PARSE_FLAG_NO_DEFAULTS) != 0);

	i_zero(&root);
	i_zero(&internal);
	root.path = path;
	internal.path = "Internal defaults";
	ctx.cur_input = &internal;
	ctx.expand_values = (flags & CONFIG_PARSE_FLAG_EXPAND_VALUES) != 0;
	if ((flags & CONFIG_PARSE_FLAG_PREFIXES_IN_FILTERS) != 0)
		config_parser_get_filter_name_prefixes(&ctx);
	hash_table_create(&ctx.seen_settings, ctx.pool, 0, str_hash, strcmp);

	p_array_init(&ctx.all_filter_parsers, ctx.pool, 128);
	hash_table_create(&ctx.all_filter_parsers_hash, ctx.pool, 0,
			  config_filter_hash, config_filters_cmp);
	hash_table_create(&ctx.all_include_groups, ctx.pool, 0,
			  str_hash, strcmp);
	ctx.cur_section = p_new(ctx.pool, struct config_section_stack, 1);
	/* Global settings filter must be the first. */
	struct config_filter root_filter = { };
	struct config_filter_parser *root_filter_parser =
		config_add_new_parser(&ctx, &root_filter, NULL);
	/* Default global settings filter must be the second. This is important
	   so it will be in the correct position when dumping the config. Add
	   all default settings into this filter. */
	struct config_filter root_default_filter = {
		.default_settings = TRUE,
	};
	struct config_filter_parser *default_filter_parser =
		config_add_new_parser(&ctx, &root_default_filter, NULL);
	ctx.cur_section->filter_parser = default_filter_parser;

	ctx.prefixed_value = str_new(ctx.pool, 256);
	full_line = str_new(default_pool, 512);

	/* read the config until dovecot_config_version line */
	ctx.cur_input = &root;
	ctx.cur_input->input = fd != -1 ?
		i_stream_create_fd_autoclose(&fd, SIZE_MAX) :
		i_stream_create_from_data("", 0);
	i_stream_set_return_partial_line(ctx.cur_input->input, TRUE);
	struct istream *orig_input = ctx.cur_input->input;

	while (ctx.dovecot_config_version == NULL &&
	       (line = i_stream_read_next_line(ctx.cur_input->input)) != NULL) {
		struct config_line config_line;
		ctx.cur_input->linenum++;
		config_parse_line(&ctx, line, full_line, &config_line);
		(void)config_parser_get_version(&ctx, &config_line);
		if (ctx.error != NULL) {
			*error_r = config_file_get_input_error(&ctx);
			ret = -2;
			break;
		}
	}

	/* initialize defaults, which may depend on dovecot_config_version */
	if ((flags & CONFIG_PARSE_FLAG_NO_DEFAULTS) == 0) {
		config_parser_add_services(&ctx, service_info_idx);
		for (i = 0; i < count; i++) T_BEGIN {
			config_parser_add_info_defaults(&ctx, all_infos[i]);
		} T_END;
	}
	if (hook_config_parser_begin != NULL &&
	    (flags & CONFIG_PARSE_FLAG_EXTERNAL_HOOKS) != 0) T_BEGIN {
		hook_config_parser_begin(&ctx);
	} T_END;

	if ((flags & CONFIG_PARSE_FLAG_DEFAULT_VERSION) != 0) {
		/* Use default settings. Set dovecot_storage_version to the
		   latest version, so it won't cause a failure.

		   When building from git we don't know the latest version, so
		   just use 9999. The version validity checks are disabled for
		   git builds, so this should work. */
		const char *version = version_is_valid(DOVECOT_VERSION) ?
			DOVECOT_VERSION : "9999";
		const char *prefixed_version =
			t_strdup_printf("%c%s", CONFIG_VALUE_PREFIX_EXPANDED, version);
		if (config_apply_exact_line(&ctx, NULL, "dovecot_storage_version",
					    prefixed_version) < 0)
			i_panic("Couldn't set default dovecot_storage_version: %s", ctx.error);
	}
	unsigned int old_linenum = ctx.cur_input->linenum;

	internal.path = "Internal config_import";
	ctx.cur_input->linenum = 0;
	ctx.cur_input->input = config_import == NULL ?
		i_stream_create_from_data("", 0) :
		i_stream_create_from_data(str_data(config_import),
					  str_len(config_import));
	i_stream_set_name(ctx.cur_input->input, "<internal config_import>");

	ctx.cur_section->filter_parser = default_filter_parser;
	config_parser_set_change_counter(&ctx, CONFIG_PARSER_CHANGE_DEFAULTS);
	while (ret == 0 &&
	       (line = i_stream_read_next_line(ctx.cur_input->input)) != NULL) {
		struct config_line config_line;
		ctx.cur_input->linenum++;
		config_parse_line(&ctx, line, full_line, &config_line);
		if (config_line.type == CONFIG_LINE_TYPE_CONTINUE)
			continue;

		T_BEGIN {
			config_parser_apply_line(&ctx, &config_line);
		} T_END;
		if (ctx.error != NULL) {
			i_panic("Error in internal import configuration line %d: %s",
				ctx.cur_input->linenum, ctx.error);
		}
	}
	i_stream_destroy(&ctx.cur_input->input);
	ctx.cur_input->linenum = old_linenum;

	/* continue reading the actual configuration file */
	ctx.cur_section->filter_parser = root_filter_parser;
	config_parser_set_change_counter(&ctx, CONFIG_PARSER_CHANGE_EXPLICIT);

	ctx.cur_input = &root;
	ctx.cur_input->input = orig_input;

prevfile:
	while (ret == 0 &&
	       (line = i_stream_read_next_line(ctx.cur_input->input)) != NULL) {
		struct config_line config_line;
		ctx.cur_input->linenum++;
		config_parse_line(&ctx, line, full_line, &config_line);
		if (config_line.type == CONFIG_LINE_TYPE_CONTINUE)
			continue;

		if (!config_parser_get_version(&ctx, &config_line) &&
		    ctx.error == NULL) T_BEGIN {
			old_settings_handle(&ctx, &config_line);
			config_parser_apply_line(&ctx, &config_line);
		} T_END;

		if (ctx.error != NULL) {
			*error_r = config_file_get_input_error(&ctx);
			ret = -2;
			break;
		}
		str_truncate(full_line, 0);
	}

	i_stream_destroy(&ctx.cur_input->input);
	ctx.cur_input = ctx.cur_input->prev;
	if (line == NULL && ctx.cur_input != NULL)
		goto prevfile;

	while (ctx.cur_input != NULL) {
		i_stream_destroy(&ctx.cur_input->input);
		ctx.cur_input = ctx.cur_input->prev;
	}

	if (ret == 0) {
		ret = config_parse_finish(&ctx, flags, dump_filter,
					  config_r, error_r);
	}

	if (ret == 0 && !dump_defaults &&
	    (flags & CONFIG_PARSE_FLAG_NO_DEFAULTS) == 0) {
		const char *version = config_parsed_get_setting(*config_r,
			"master_service", "dovecot_storage_version");
		if (version[0] == '\0') {
			*error_r = "dovecot_storage_version setting must be set";
			ret = -2;
		}
	}

	hash_table_destroy(&ctx.seen_settings);
	hash_table_destroy(&ctx.all_keys);
	hash_table_destroy(&ctx.all_filter_parsers_hash);
	hash_table_destroy(&ctx.all_include_groups);
	str_free(&full_line);
	pool_unref(&ctx.pool);
	return ret < 0 ? ret : 1;
}

bool config_parsed_get_version(const struct config_parsed *config,
			       const char **version_r)
{
	*version_r = config->dovecot_config_version;
	return config->dovecot_config_version != NULL;
}

const ARRAY_TYPE(const_string) *
config_parsed_get_errors(const struct config_parsed *config)
{
	return &config->errors;
}

struct config_filter_parser *
config_parsed_get_global_filter_parser(const struct config_parsed *config)
{
	return config->filter_parsers[0];
}

struct config_filter_parser *
config_parsed_get_global_default_filter_parser(const struct config_parsed *config)
{
	return config->filter_parsers[1];
}

struct config_filter_parser *const *
config_parsed_get_filter_parsers(const struct config_parsed *config)
{
	return config->filter_parsers;
}

HASH_TABLE_TYPE(config_key)
config_parsed_get_all_keys(const struct config_parsed *config)
{
	return config->all_keys;
}

static void
config_parsed_strlist_append(string_t *keyvals,
			     const ARRAY_TYPE(const_string) *values,
			     const ARRAY_TYPE(const_string) *drop_values)
{
	if (values == NULL || !array_is_created(values))
		return;

	const char *const *strlist, *const *drop_strlist;
	unsigned int i, j, len, drop_len;
	if (drop_values != NULL && array_is_created(drop_values))
		drop_strlist = array_get(drop_values, &drop_len);
	else {
		drop_strlist = NULL;
		drop_len = 0;
	}

	strlist = array_get(values, &len);
	for (i = 0; i < len; i += 2) {
		i_assert(strlist[i][0] == CONFIG_VALUE_PREFIX_EXPANDED);
		i_assert(strlist[i + 1][0] == CONFIG_VALUE_PREFIX_EXPANDED);

		if (str_len(keyvals) > 0)
			str_append_c(keyvals, '\t');
		for (j = 0; j < drop_len; j += 2) {
			if (strcmp(strlist[i] + 1, drop_strlist[j]) == 0)
				break;
		}
		if (j == drop_len) {
			str_append_tabescaped(keyvals, strlist[i] + 1);
			str_append_c(keyvals, '=');
			str_append_tabescaped(keyvals, strlist[i + 1] + 1);
		}
	}
}

static const char *
config_parsed_get_setting_full(const struct config_parsed *config,
			       const char *info_name, const char *key,
			       unsigned int *change_counter_r)
{
	struct config_filter_parser *filter_parser =
		config_parsed_get_global_filter_parser(config);
	struct config_filter_parser *default_filter_parser =
		config_parsed_get_global_default_filter_parser(config);
	const struct config_module_parser *l = filter_parser->module_parsers;
	const struct config_module_parser *ldef =
		default_filter_parser->module_parsers;
	unsigned int info_idx, key_idx;

	for (info_idx = 0; l[info_idx].info != NULL; info_idx++) {
		if (strcmp(l[info_idx].info->name, info_name) == 0)
			break;
	}
	if (l[info_idx].info == NULL ||
	    !setting_parser_info_find_key(l[info_idx].info, key, &key_idx)) {
		i_panic("BUG: Couldn't find setting with info=%s key=%s",
			info_name, key);
	}

	const struct setting_define *def = &l[info_idx].info->defines[key_idx];

	if (change_counter_r != NULL) {
		*change_counter_r = l[info_idx].change_counters[key_idx];
		return NULL;
	}
	/* Custom handler for the import_environment strlist setting. The
	   calling function expects a string of key=value pairs. See
	   master_service_get_import_environment_keyvals() for the original
	   implementation. */
	if (strcmp(key, "import_environment") == 0) {
		string_t *keyvals = t_str_new(64);
		const ARRAY_TYPE(const_string) *strlist_set =
			l[info_idx].settings[key_idx].list.prefixed_values;
		const ARRAY_TYPE(const_string) *strlist_defaults =
			ldef[info_idx].settings[key_idx].list.prefixed_values;
		config_parsed_strlist_append(keyvals, strlist_set, NULL);
		config_parsed_strlist_append(keyvals, strlist_defaults, strlist_set);
		return str_c(keyvals);
	}

	i_assert(def->type != SET_STRLIST && def->type != SET_BOOLLIST &&
		 def->type != SET_FILTER_ARRAY);
	if (l[info_idx].change_counters[key_idx] != 0)
		return set_str_expanded(&l[info_idx].settings[key_idx]);
	if (ldef[info_idx].change_counters[key_idx] != 0)
		return set_str_expanded(&ldef[info_idx].settings[key_idx]);

	const void *value = CONST_PTR_OFFSET(l[info_idx].info->defaults, def->offset);
	string_t *str = t_str_new(64);
	if (!config_export_type(str, value, def->type))
		i_unreached();
	return str_c(str);
}

const char *
config_parsed_get_setting(const struct config_parsed *config,
			  const char *info_name, const char *key)
{
	return config_parsed_get_setting_full(config, info_name, key, NULL);
}

unsigned int
config_parsed_get_setting_change_counter(const struct config_parsed *config,
					 const char *info_name, const char *key)
{
	unsigned int change_counter;

	(void)config_parsed_get_setting_full(config, info_name, key,
					     &change_counter);
	return change_counter;
}

const struct setting_define *
config_parsed_key_lookup(const struct config_parsed *config, const char *key)
{
	struct config_parser_key *config_key =
		hash_table_lookup(config->all_keys, key);
	if (config_key == NULL)
		return NULL;
	return &all_infos[config_key->info_idx]->defines[config_key->define_idx];
}

static bool config_filter_tree_has_settings(struct config_filter_parser *filter,
					    unsigned int parser_idx)
{
	if (filter->module_parsers[parser_idx].settings != NULL)
		return TRUE;
	for (filter = filter->children_head; filter != NULL; filter = filter->next) {
		if (config_filter_tree_has_settings(filter, parser_idx))
			return TRUE;
	}
	return FALSE;
}

static bool
config_include_group_filters_have_settings(
	struct config_include_group_filters *group_filters,
	unsigned int parser_idx)
{
	struct config_filter_parser *group_filter;

	/* See if this group modifies the wanted parser. Check the group's
	   root filter and all of its child filters. For example
	   group @foo bar { namespace inbox { separator=/ } } needs to
	   returns TRUE for namespace parser, which is modified in the child
	   namespace filter. */
	array_foreach_elem(&group_filters->filters, group_filter) {
		if (config_filter_tree_has_settings(group_filter, parser_idx))
			return TRUE;
	}
	return FALSE;
}

bool config_parsed_get_includes(const struct config_parsed *config,
				const struct config_filter_parser *filter,
				unsigned int parser_idx,
				ARRAY_TYPE(config_include_group) *groups)
{
	array_clear(groups);

	if (!array_is_created(&filter->include_groups))
		return FALSE;

	const struct config_include_group *group;
	array_foreach(&filter->include_groups, group) {
		struct config_include_group_filters *group_filters =
			hash_table_lookup(config->include_groups, group->label);
		if (group_filters == NULL)
			continue;

		if (config_include_group_filters_have_settings(group_filters, parser_idx))
			array_push_back(groups, group);
	}
	return array_count(groups) > 0;
}

const ARRAY_TYPE(config_path) *
config_parsed_get_paths(const struct config_parsed *config)
{
	return &config->seen_paths;
}

void config_parsed_free(struct config_parsed **_config)
{
	struct config_parsed *config = *_config;

	if (config == NULL)
		return;
	*_config = NULL;

	hash_table_destroy(&config->include_groups);
	hash_table_destroy(&config->all_keys);
	pool_unref(&config->pool);
}

static int config_service_cmp(const struct config_service *s1,
			      const struct config_service *s2)
{
	return strcmp(s1->set->name, s2->set->name);
}

static bool config_have_info_dependency(const struct setting_parser_info *info)
{
	if (info->plugin_dependency == NULL)
		return TRUE;
	const char *path = t_strconcat(MODULEDIR"/", info->plugin_dependency,
				       MODULE_SUFFIX, NULL);
	struct stat st;
	return stat(path, &st) == 0;
}

static void
config_parse_load_module_paths(const char *const *paths,
			       const struct module_dir_load_settings *mod_set)
{
	for (unsigned int i = 0; paths[i] != NULL; i++) {
		const char *dir;
		const char *fname = strrchr(paths[i], '/');
		if (fname == NULL)
			i_fatal("Missing directory for %s", paths[i]);
		dir = t_strdup_until(paths[i], fname++);

		const char *const fnames[2] = { fname, NULL };
		modules = module_dir_load_missing(modules, dir, fnames,
						  mod_set);
	}
}

void config_parse_load_modules(bool dump_config_import)
{
	struct module_dir_load_settings mod_set;
	struct module *m;
	const struct setting_parser_info **infos;
	ARRAY_TYPE(setting_parser_info_p) new_infos;
	ARRAY_TYPE(config_service) new_services;
	const struct config_service *services;
	unsigned int i, count;

	i_zero(&mod_set);
	mod_set.abi_version = DOVECOT_ABI_VERSION;
	const char *module_paths = getenv("CONFIG_MODULES");
	if (module_paths == NULL)
		modules = module_dir_load(CONFIG_MODULE_DIR, NULL, &mod_set);
	else {
		/* Explicit list of config modules to load explicitly.
		   Used by Pigeonhole testsuite. */
		config_parse_load_module_paths(t_strsplit(module_paths, ":"),
					       &mod_set);

	}
	module_dir_init(modules);

	config_import = str_new(default_pool, 10240);
	str_append(config_import, stats_metric_defaults);
	str_append(config_import, mailbox_defaults);
	i_array_init(&new_infos, 64);
	/* drop any default infos which depend on plugins that don't exist */
	for (i = 0; all_infos[i] != NULL; i++) {
		if (config_have_info_dependency(all_infos[i]))
			array_push_back(&new_infos, &all_infos[i]);
	}

	i_array_init(&new_services, 64);
	for (m = modules; m != NULL; m = m->next) {
		infos = module_get_symbol_quiet(m,
			t_strdup_printf("%s_set_infos", m->name));
		if (infos != NULL) {
			for (i = 0; infos[i] != NULL; i++)
				array_push_back(&new_infos, &infos[i]);
		}

		const char *const *import = module_get_symbol_quiet(m,
			t_strdup_printf("%s_config_import", m->name));
		if (import != NULL) {
			str_append(config_import, *import);
			str_append_c(config_import, '\n');
		}
		services = module_get_symbol_quiet(m,
			t_strdup_printf("%s_services_array", m->name));
		if (services != NULL) {
			for (count = 0; services[count].set != NULL; count++) ;
			array_append(&new_services, services, count);
		} else {
			struct config_service new_service = { };
			new_service.set = module_get_symbol_quiet(m,
				t_strdup_printf("%s_service_settings", m->name));
			if (new_service.set != NULL) {
				new_service.defaults = module_get_symbol_quiet(m,
					t_strdup_printf("%s_service_settings_defaults", m->name));
				array_push_back(&new_services, &new_service);
			}
		}
	}
	array_append_zero(&new_infos);
	all_infos = array_front(&new_infos);
	infos_free_at_deinit = new_infos;

	if (array_count(&new_services) > 0) {
		/* module added new services. update the defaults. */
		for (i = 0; config_all_services[i].set != NULL; i++)
			array_push_back(&new_services, &config_all_services[i]);
		array_sort(&new_services, config_service_cmp);
		array_append_zero(&new_services);
		config_all_services = array_front(&new_services);
		services_free_at_deinit = new_services;
	} else {
		array_free(&new_services);
	}
	if (dump_config_import)
		puts(str_c(config_import));
}

void config_parser_deinit(void)
{
	if (array_is_created(&services_free_at_deinit))
		array_free(&services_free_at_deinit);
	if (array_is_created(&infos_free_at_deinit))
		array_free(&infos_free_at_deinit);
	str_free(&config_import);
}
