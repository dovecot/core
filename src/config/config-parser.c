/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "hash.h"
#include "llist.h"
#include "strescape.h"
#include "istream.h"
#include "module-dir.h"
#include "settings.h"
#include "settings-parser.h"
#include "service-settings.h"
#include "master-service.h"
#include "master-service-settings.h"
#include "master-service-ssl-settings.h"
#include "all-settings.h"
#include "old-set-parser.h"
#include "config-request.h"
#include "config-dump-full.h"
#include "config-parser-private.h"

#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#ifdef HAVE_GLOB_H
#  include <glob.h>
#endif

#ifndef GLOB_BRACE
#  define GLOB_BRACE 0
#endif

#define DNS_LOOKUP_TIMEOUT_SECS 30
#define DNS_LOOKUP_WARN_SECS 5

struct config_parser_key {
	struct config_parser_key *prev, *next;

	/* Index number to get setting_parser_info from all_infos[] or
	   module_parsers[] */
	unsigned int info_idx;
	/* Index number inside setting_parser_info->defines[] */
	unsigned int define_idx;
};

struct config_parsed {
	pool_t pool;
	struct config_filter_parser *const *filter_parsers;
	struct config_module_parser *module_parsers;
	ARRAY_TYPE(const_string) errors;
};

ARRAY_DEFINE_TYPE(setting_parser_info_p, const struct setting_parser_info *);

static const enum settings_parser_flags settings_parser_flags =
	SETTINGS_PARSER_FLAG_IGNORE_UNKNOWN_KEYS |
	SETTINGS_PARSER_FLAG_TRACK_CHANGES;

struct module *modules;
void (*hook_config_parser_begin)(struct config_parser_context *ctx);
int (*hook_config_parser_end)(struct config_parser_context *ctx,
			      const char **error_r);

static ARRAY_TYPE(config_service) services_free_at_deinit = ARRAY_INIT;
static ARRAY_TYPE(setting_parser_info_p) infos_free_at_deinit = ARRAY_INIT;

static struct config_filter_parser *
config_filter_parser_find(struct config_parser_context *ctx,
			  const struct config_filter *filter);
static struct config_section_stack *
config_add_new_section(struct config_parser_context *ctx);
static void
config_add_new_parser(struct config_parser_context *ctx,
		      struct config_section_stack *cur_section);
static int
config_apply_exact_line(struct config_parser_context *ctx, const char *key,
			const char *value);

void config_parser_set_change_counter(struct config_parser_context *ctx,
				      uint8_t change_counter)
{
	struct config_module_parser *module_parsers =
		ctx->cur_section->module_parsers;

	ctx->change_counter = change_counter;
	for (unsigned int i = 0; module_parsers[i].info != NULL; i++) {
		if (module_parsers[i].parser != NULL) {
			settings_parse_set_change_counter(module_parsers[i].parser,
							  change_counter);
		}
	}
}

static struct config_section_stack *
config_parser_add_filter_array(struct config_parser_context *ctx,
			       const char *filter_key, const char *name)
{
	config_parser_set_change_counter(ctx, CONFIG_PARSER_CHANGE_INTERNAL);
	if (config_apply_exact_line(ctx, filter_key, name) < 0) {
		i_panic("Failed to add %s %s: %s", filter_key, name,
			ctx->error);
	}
	config_parser_set_change_counter(ctx, CONFIG_PARSER_CHANGE_EXPLICIT);

	struct config_section_stack *section;
	section = config_add_new_section(ctx);
	section->filter.filter_name =
		p_strdup_printf(ctx->pool, "%s/%s", filter_key, name);
	section->filter.filter_name_array = TRUE;
	section->is_filter = TRUE;
	/* use cur_section's filter_parser as parent */
	section->filter_parser = ctx->cur_section->filter_parser;
	config_add_new_parser(ctx, section);
	section->filter_parser->filter_required_setting_seen = TRUE;
	return section;
}

static void
config_parser_add_service_default_struct(struct config_parser_context *ctx,
					 unsigned int service_info_idx,
					 const struct service_settings *default_set)
{
	const struct setting_parser_info *info = all_infos[service_info_idx];
	string_t *value_str = t_str_new(64);
	bool dump;

	config_parser_set_change_counter(ctx, CONFIG_PARSER_CHANGE_INTERNAL);
	for (unsigned int i = 0; info->defines[i].key != NULL; i++) {
		const void *value = CONST_PTR_OFFSET(default_set,
						     info->defines[i].offset);
		i_assert(value != NULL);

		str_truncate(value_str, 0);
		if (!config_export_type(value_str, value, NULL,
					info->defines[i].type, TRUE, &dump))
			continue;

		if (config_apply_line(ctx, info->defines[i].key,
				      str_c(value_str), NULL) < 0) {
			i_panic("Failed to add default setting %s=%s for service %s: %s",
				info->defines[i].key, str_c(value_str),
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
	struct config_module_parser *orig_module_parsers =
		ctx->cur_section->module_parsers;
	const char *p;

	for (unsigned int i = 0; defaults[i].key != NULL; i++) T_BEGIN {
		const char *key = defaults[i].key;

		if ((p = strchr(key, '/')) != NULL &&
		    (p = strchr(p + 1, '/')) != NULL) {
			/* *_listener filter */
			const char *escaped_key = t_strdup_until(key, p);
			struct config_filter filter = {
				.filter_name = settings_section_unescape(escaped_key),
				.filter_name_array = TRUE,
				.parent = &orig_filter_parser->filter,
			};
			struct config_filter_parser *filter_parser =
				config_filter_parser_find(ctx, &filter);
			if (filter_parser == NULL) {
				ctx->cur_section->filter = filter;
				ctx->cur_section->filter.filter_name =
					p_strdup(ctx->pool, filter.filter_name);
				ctx->cur_section->filter_parser = orig_filter_parser;
				config_add_new_parser(ctx, ctx->cur_section);
				ctx->cur_section->filter_parser->filter_required_setting_seen = TRUE;
			} else {
				ctx->cur_section->filter_parser = filter_parser;
				ctx->cur_section->module_parsers =
					ctx->cur_section->filter_parser->module_parsers;
				ctx->cur_section->filter = filter_parser->filter;
			}
			key = p + 1;
		}

		config_parser_set_change_counter(ctx, CONFIG_PARSER_CHANGE_INTERNAL);
		if (config_apply_line(ctx, key, defaults[i].value, NULL) < 0) {
			i_panic("Failed to add default setting %s=%s for service %s: %s",
				defaults[i].key, defaults[i].value,
				service_name, ctx->error);
		}
		config_parser_set_change_counter(ctx, CONFIG_PARSER_CHANGE_EXPLICIT);

		ctx->cur_section->filter_parser = orig_filter_parser;
		ctx->cur_section->module_parsers = orig_module_parsers;
		ctx->cur_section->filter = orig_filter_parser->filter;
	} T_END;
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

static bool
config_parser_is_in_localremote(struct config_section_stack *section)
{
	const struct config_filter *filter = &section->filter;

	do {
		if (filter->local_name != NULL || filter->local_bits > 0 ||
		    filter->remote_bits > 0)
			return TRUE;
		filter = filter->parent;
	} while (filter != NULL);
	return FALSE;
}

static void
section_stack_write(string_t *str, struct config_section_stack *section)
{
	if (section == NULL)
		return;

	section_stack_write(str, section->prev);
	if (!section->is_filter && section->key != NULL)
		str_printfa(str, "%s { ", section->key);
}

static const char *
get_setting_full_path(struct config_parser_context *ctx, const char *key)
{
	string_t *str = t_str_new(128);

	section_stack_write(str, ctx->cur_section);
	str_append(str, key);
	return str_c(str);
}

static bool
config_is_filter_name(struct config_parser_context *ctx, const char *key,
		      const struct setting_define **def_r)
{
	struct config_parser_key *config_key;
	const struct setting_define *def;

	config_key = hash_table_lookup(ctx->all_keys, key);
	if (config_key == NULL)
		return FALSE;

	def = &all_infos[config_key->info_idx]->defines[config_key->define_idx];
	if (def->type != SET_FILTER_NAME && def->type != SET_FILTER_ARRAY)
		return FALSE;

	*def_r = def;
	return TRUE;
}

static int
config_apply_exact_line(struct config_parser_context *ctx, const char *key,
			const char *value)
{
	struct config_parser_key *config_key;

	if (ctx->cur_section->filter_def != NULL &&
	    !ctx->cur_section->filter_parser->filter_required_setting_seen &&
	    ctx->cur_section->filter_def->required_setting != NULL &&
	    strcmp(key, ctx->cur_section->filter_def->required_setting) == 0)
		ctx->cur_section->filter_parser->filter_required_setting_seen = TRUE;

	/* if key is strlist/key, lookup only "strlist" */
	config_key = hash_table_lookup(ctx->all_keys, t_strcut(key, '/'));
	if (config_key == NULL)
		return 0;

	for (; config_key != NULL; config_key = config_key->next) {
		struct config_module_parser *l =
			&ctx->cur_section->module_parsers[config_key->info_idx];
		if (l->parser == NULL) {
			l->parser = settings_parser_init(ctx->pool,
				all_infos[config_key->info_idx],
				settings_parser_flags);
			settings_parse_set_change_counter(l->parser,
							  ctx->change_counter);
		}
		if (settings_parse_keyidx_value(l->parser,
				config_key->define_idx, key, value) == 0) {
			/* FIXME: remove once auth does support these. */
			if (strcmp(l->info->name, "auth") == 0 &&
			    config_parser_is_in_localremote(ctx->cur_section)) {
				ctx->error = p_strconcat(ctx->pool,
					"Auth settings not supported inside local/remote blocks: ",
					key, NULL);
				return -1;
			}
		} else {
			ctx->error = settings_parser_get_error(l->parser);
			return -1;
		}
	}
	return 1;
}

int config_apply_line(struct config_parser_context *ctx,
		      const char *key_with_path,
		      const char *value, const char **full_key_r)
{
	struct config_filter orig_filter = ctx->cur_section->filter;
	struct config_module_parser *orig_module_parsers =
		ctx->cur_section->module_parsers;
	struct config_filter_parser *filter_parser, *orig_filter_parser;
	const char *p, *key;
	int ret = 0;

	orig_filter_parser = ctx->cur_section->filter_parser;
	while ((p = strchr(key_with_path, '/')) != NULL &&
	       (p = strchr(p + 1, '/')) != NULL) {
		/* Support e.g. service/imap/inet_listener/imap prefix here.
		   These prefixes are used by default settings and
		   old-set-parser. */
		struct config_filter filter = {
			.parent = &ctx->cur_section->filter,
			.filter_name = t_strdup_until(key_with_path, p),
			.filter_name_array = TRUE,
		};
		filter_parser = config_filter_parser_find(ctx, &filter);
		if (filter_parser == NULL)
			break;
		key_with_path = p + 1;
		ctx->cur_section->filter_parser = filter_parser;
		ctx->cur_section->module_parsers =
			ctx->cur_section->filter_parser->module_parsers;
		ctx->cur_section->filter = filter_parser->filter;
	}
	/* the only '/' left should be if key is under strlist/ */
	key = key_with_path;

	if (ctx->cur_section->filter.filter_name_array) {
		/* first try the filter name-specific prefix, so e.g.
		   inet_listener { ssl=yes } won't try to change the global
		   ssl setting. */
		const char *filter_key =
			t_strcut(ctx->cur_section->filter.filter_name, '/');
		const char *key2 = t_strdup_printf("%s_%s", filter_key, key);
		ret = config_apply_exact_line(ctx, key2, value);
		if (ret > 0 && full_key_r != NULL)
			*full_key_r = key2;
	}
	if (ret == 0) {
		ret = config_apply_exact_line(ctx, key, value);
		if (full_key_r != NULL)
			*full_key_r = key;
	}
	ctx->cur_section->filter_parser = orig_filter_parser;
	ctx->cur_section->module_parsers = orig_module_parsers;
	ctx->cur_section->filter = orig_filter;
	if (ret == 0) {
		ctx->error = p_strconcat(ctx->pool, "Unknown setting: ",
					 get_setting_full_path(ctx, key), NULL);
		return -1;
	}
	return 0;
}

static int
config_apply_error(struct config_parser_context *ctx, const char *key)
{
	struct config_parser_key *config_key;

	/* Couldn't get value for the setting, but we're delaying error
	   handling. Mark all settings parsers containing this key as failed.
	   See config-parser.h for details. */
	config_key = hash_table_lookup(ctx->all_keys, t_strcut(key, '/'));
	if (config_key == NULL)
		return -1;

	for (; config_key != NULL; config_key = config_key->next) {
		struct config_module_parser *l =
			&ctx->cur_section->module_parsers[config_key->info_idx];
		if (l->delayed_error == NULL)
			l->delayed_error = ctx->error;
		ctx->error = NULL;
	}
	return 0;
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

static void
config_add_new_parser(struct config_parser_context *ctx,
		      struct config_section_stack *cur_section)
{
	struct config_filter_parser *filter_parser;

	filter_parser = p_new(ctx->pool, struct config_filter_parser, 1);
	filter_parser->filter = cur_section->filter;
	if (ctx->cur_input->linenum == 0) {
		filter_parser->file_and_line =
			p_strdup(ctx->pool, ctx->cur_input->path);
	} else {
		filter_parser->file_and_line =
			p_strdup_printf(ctx->pool, "%s:%d",
					ctx->cur_input->path,
					ctx->cur_input->linenum);
	}
	filter_parser->module_parsers = cur_section->prev == NULL ?
		ctx->root_module_parsers :
		config_module_parsers_init(ctx->pool);
	array_push_back(&ctx->all_filter_parsers, &filter_parser);

	if (cur_section->filter_parser != NULL) {
		DLLIST2_APPEND(&cur_section->filter_parser->children_head,
			       &cur_section->filter_parser->children_tail,
			       filter_parser);
	}

	cur_section->filter_parser = filter_parser;
	cur_section->module_parsers = filter_parser->module_parsers;
}

static struct config_section_stack *
config_add_new_section(struct config_parser_context *ctx)
{
	struct config_section_stack *section;

	section = p_new(ctx->pool, struct config_section_stack, 1);
	section->prev = ctx->cur_section;
	section->filter = ctx->cur_section->filter;
	section->filter_parser = ctx->cur_section->filter_parser;
	section->module_parsers = ctx->cur_section->module_parsers;

	section->open_path = p_strdup(ctx->pool, ctx->cur_input->path);
	section->open_linenum = ctx->cur_input->linenum;
	return section;
}

static struct config_filter_parser *
config_filter_parser_find(struct config_parser_context *ctx,
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

static bool
config_filter_add_new_filter(struct config_parser_context *ctx,
			     const struct config_line *line)
{
	const char *key = line->key, *value = line->value;
	struct config_filter *filter = &ctx->cur_section->filter;
	struct config_filter *parent = &ctx->cur_section->prev->filter;
	struct config_filter_parser *filter_parser;
	const struct setting_define *filter_def = NULL;
	const char *error;

	i_zero(filter);
	filter->parent = parent;

	if (strcmp(key, "protocol") == 0) {
		if (parent->service != NULL)
			ctx->error = "Nested protocol { protocol { .. } } block not allowed";
		else if (parent->filter_name != NULL)
			ctx->error = p_strdup_printf(ctx->pool,
				"%s { protocol { .. } } not allowed (use protocol { %s { .. } } instead)",
				t_strcut(parent->filter_name, '/'),
				t_strcut(parent->filter_name, '/'));
		else
			filter->service = p_strdup(ctx->pool, value);
	} else if (strcmp(key, "local") == 0) {
		if (parent->remote_bits > 0)
			ctx->error = "remote { local { .. } } not allowed (use local { remote { .. } } instead)";
		else if (parent->service != NULL)
			ctx->error = "protocol { local { .. } } not allowed (use local { protocol { .. } } instead)";
		else if (parent->local_name != NULL)
			ctx->error = "local_name { local { .. } } not allowed (use local { local_name { .. } } instead)";
		else if (parent->filter_name != NULL)
			ctx->error = p_strdup_printf(ctx->pool,
				"%s { local { .. } } not allowed (use local { %s { .. } } instead)",
				t_strcut(parent->filter_name, '/'),
				t_strcut(parent->filter_name, '/'));
		else if (config_parse_net(value, &filter->local_net,
					  &filter->local_bits, &error) < 0)
			ctx->error = p_strdup(ctx->pool, error);
		else if (parent->local_bits > filter->local_bits ||
			 (parent->local_bits > 0 &&
			  !net_is_in_network(&filter->local_net,
					     &parent->local_net,
					     parent->local_bits)))
			ctx->error = "local net1 { local net2 { .. } } requires net2 to be inside net1";
		else
			filter->local_host = p_strdup(ctx->pool, value);
	} else if (strcmp(key, "local_name") == 0) {
		if (parent->remote_bits > 0)
			ctx->error = "remote { local_name { .. } } not allowed (use local_name { remote { .. } } instead)";
		else if (parent->service != NULL)
			ctx->error = "protocol { local_name { .. } } not allowed (use local_name { protocol { .. } } instead)";
		else if (parent->filter_name != NULL)
			ctx->error = p_strdup_printf(ctx->pool,
				"%s { local_name { .. } } not allowed (use local_name { %s { .. } } instead)",
				t_strcut(parent->filter_name, '/'),
				t_strcut(parent->filter_name, '/'));
		else
			filter->local_name = p_strdup(ctx->pool, value);
	} else if (strcmp(key, "remote") == 0) {
		if (parent->service != NULL)
			ctx->error = "protocol { remote { .. } } not allowed (use remote { protocol { .. } } instead)";
		else if (parent->filter_name != NULL)
			ctx->error = p_strdup_printf(ctx->pool,
				"%s { remote { .. } } not allowed (use remote { %s { .. } } instead)",
				t_strcut(parent->filter_name, '/'),
				t_strcut(parent->filter_name, '/'));
		else if (config_parse_net(value, &filter->remote_net,
					  &filter->remote_bits, &error) < 0)
			ctx->error = p_strdup(ctx->pool, error);
		else if (parent->remote_bits > filter->remote_bits ||
			 (parent->remote_bits > 0 &&
			  !net_is_in_network(&filter->remote_net,
					     &parent->remote_net,
					     parent->remote_bits)))
			ctx->error = "remote net1 { remote net2 { .. } } requires net2 to be inside net1";
		else
			filter->remote_host = p_strdup(ctx->pool, value);
	} else if (config_is_filter_name(ctx, key, &filter_def)) {
		if (filter_def->type == SET_FILTER_NAME) {
			if (value[0] != '\0' || line->value_quoted) {
				ctx->error = p_strdup_printf(ctx->pool,
					"%s { } must not have a section name",
					key);
				return TRUE;
			}
			if (parent->filter_name != NULL &&
			    !parent->filter_name_array) {
				ctx->error = p_strdup_printf(ctx->pool,
					"Nested named filters not allowed: %s { %s { .. } }",
					parent->filter_name, key);
				return FALSE;
			}
			filter->filter_name = p_strdup(ctx->pool, key);
		} else {
			if (parent->filter_name != NULL &&
			    !parent->filter_name_array) {
				ctx->error = p_strdup_printf(ctx->pool,
					"%s { %s { .. } } not allowed (use %s { %s { .. } } instead)",
					parent->filter_name, key, key, parent->filter_name);
				return FALSE;
			}
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
			    parent->filter_name_array) {
				i_assert(parent->filter_name != NULL);
				ctx->error = p_strdup_printf(ctx->pool,
					"%s { .. } not allowed under %s { .. }",
					key, t_strcut(parent->filter_name, '/'));
				return FALSE;
			}
			if (value[0] == '\0' && !line->value_quoted) {
				ctx->error = p_strdup_printf(ctx->pool,
					"%s { } is missing section name", key);
				return TRUE;
			}
			filter->filter_name =
				p_strdup_printf(ctx->pool, "%s/%s", key, value);
			filter->filter_name_array = TRUE;
		}
	} else {
		return FALSE;
	}

	filter_parser = config_filter_parser_find(ctx, filter);
	if (filter_parser != NULL) {
		ctx->cur_section->filter_parser = filter_parser;
		ctx->cur_section->module_parsers =
			ctx->cur_section->filter_parser->module_parsers;
	} else {
		if (filter_def != NULL && filter_def->type == SET_FILTER_ARRAY) {
			/* add it to the list of filter names */
			const char *escaped_value =
				settings_section_escape(value);
			if (config_apply_line(ctx, filter_def->key,
					      escaped_value, NULL) < 0) {
				i_panic("BUG: Invalid setting definitions: "
					"Failed to set %s=%s: %s",
					filter_def->key, escaped_value,
					ctx->error);
			}
		}
		config_add_new_parser(ctx, ctx->cur_section);
	}
	ctx->cur_section->is_filter = TRUE;

	if (filter_def != NULL) {
		ctx->cur_section->filter_def = filter_def;
		if (filter_def->type == SET_FILTER_ARRAY) {
			/* add the name field for the filter */
			if (config_apply_line(ctx, filter_def->filter_array_field_name,
					      value, NULL) < 0) {
				i_panic("BUG: Invalid setting definitions: "
					"Failed to set %s=%s: %s",
					filter_def->filter_array_field_name,
					value, ctx->error);
			}
		}
	}
	return TRUE;
}

static void
config_filter_parser_check(struct config_parser_context *ctx,
			   struct config_parsed *new_config,
			   struct event *event,
			   struct config_filter_parser *filter_parser)
{
	struct config_module_parser *p;
	const struct config_filter *filter;
	const char *error = NULL;
	pool_t tmp_pool;
	bool ok;

	event = event_create(event);
	for (filter = &filter_parser->filter; filter != NULL; filter = filter->parent) {
		if (filter->service != NULL)
			event_add_str(event, "protocol", filter->service);
		if (filter->local_name != NULL)
			event_add_str(event, "local_name", filter->local_name);
		if (filter->local_bits > 0)
			event_add_ip(event, "local_ip", &filter->local_net);
		if (filter->remote_bits > 0)
			event_add_ip(event, "remote_ip", &filter->remote_net);
	}

	tmp_pool = pool_alloconly_create(MEMPOOL_GROWING"config parsers check", 1024);
	for (p = filter_parser->module_parsers; p->info != NULL; p++) {
		if (p->parser == NULL)
			continue;
		p_clear(tmp_pool);
		struct setting_parser_context *tmp_parser =
			settings_parser_dup(p->parser, tmp_pool);
		settings_parse_var_skip(tmp_parser);
		T_BEGIN {
			ok = settings_parser_check(tmp_parser, tmp_pool,
						   event, &error);
		} T_END_PASS_STR_IF(!ok, &error);
		settings_parser_unref(&tmp_parser);

		if (!ok) {
			/* be sure to assert-crash early if error is missing */
			i_assert(error != NULL);
			if (!ctx->delay_errors) {
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
	const char *const *set_value;
	enum setting_type set_type;

	module_parser = parser->module_parsers;
	for (; module_parser->info != NULL; module_parser++) {
		if (module_parser->parser == NULL)
			continue;
		const char *lookup_key = key;
		set_value = settings_parse_get_value(module_parser->parser,
						     &lookup_key, &set_type);
		if (set_value != NULL &&
		    settings_parse_get_change_counter(module_parser->parser, lookup_key) != 0) {
			i_assert(set_type == SET_STR || set_type == SET_ENUM);
			return *set_value;
		}
	}
	return default_value;
}

static int
config_all_parsers_check(struct config_parser_context *ctx,
			 struct config_parsed *new_config,
			 const char **error_r)
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

	int fd = config_dump_full(new_config, CONFIG_DUMP_FULL_DEST_TEMPDIR, 0,
				  NULL);
	if (fd == -1) {
		*error_r = "Failed to write binary config file";
		return -1;
	}
	struct settings_root *set_root = settings_root_init();
	const char *const *specific_services, *error;
	if (settings_read(set_root, fd, "(temp config file)", NULL, NULL, 0,
			  &specific_services, &error) < 0) {
		*error_r = t_strdup_printf(
			"Failed to read settings from binary config file: %s",
			error);
		i_close_fd(&fd);
		settings_root_deinit(&set_root);
		return -1;
	}

	parsers = array_get(&ctx->all_filter_parsers, &count);
	i_assert(count > 0 && parsers[count-1] == NULL);
	count--;

	struct event *event = event_create(NULL);
	event_set_ptr(event, SETTINGS_EVENT_ROOT, set_root);

	/* Run check_func()s for each filter independently. If you have
	   protocol imap { ... local { ... } } blocks, it's going to check the
	   "local" filter without applying settings from the "protocol imap"
	   filter. In theory this could complain about nonexistent problems,
	   but currently such checks are rare enough that this shouldn't be a
	   practical problem. Fixing this is possible and it was done in a
	   previous version of the code, but it got in the way of cleaning up
	   the config code, so at least for now it's not done. */
	global_ssl_set = get_str_setting(parsers[0], "ssl", "");
	for (i = 0; i < count; i++) {
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
str_append_file(string_t *str, const char *key, const char *path,
		const char **error_r)
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

static void
config_parse_line(struct config_parser_context *ctx,
		  char *line, string_t *full_line,
		  struct config_line *config_line_r)
{
	const char *key;
	size_t len;
	char *p;

	i_zero(config_line_r);

	/* @UNSAFE: line is modified */

	/* skip whitespace */
	while (IS_WHITE(*line))
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
			if (!IS_WHITE(p[-1])) {
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
		if(!IS_WHITE(line[len-1]))
			break;
		len--;
	}
	line[len] = '\0';

	if (len >= 1 && line[len-1] == '\\') {
		/* continues in next line */
		len--;
		while (len >= 1) {
			if(!IS_WHITE(line[len-1]))
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
	while (!IS_WHITE(*line) && *line != '\0' && *line != '=')
		line++;
	if (IS_WHITE(*line)) {
		*line++ = '\0';
		while (IS_WHITE(*line)) line++;
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
		while (IS_WHITE(*line)) line++;

		if (*line == '<') {
			while (IS_WHITE(line[1])) line++;
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
			line = str_unescape(line+1);
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

	if (*line == '{')
		config_line_r->value = "";
	else {
		/* get section name */
		if (*line != '"') {
			config_line_r->value = line;
			while (!IS_WHITE(*line) && *line != '\0')
				line++;
			if (*line != '\0') {
				*line++ = '\0';
				while (IS_WHITE(*line))
					line++;
			}
		} else {
			char *value = ++line;
			while (*line != '"' && *line != '\0')
				line++;
			if (*line == '"') {
				*line++ = '\0';
				while (IS_WHITE(*line))
					line++;
				config_line_r->value = str_unescape(value);
				config_line_r->value_quoted = TRUE;
			}
		}
		if (*line != '{') {
			config_line_r->value = "Expecting '{'";
			config_line_r->type = CONFIG_LINE_TYPE_ERROR;
			return;
		}
	}
	if (line[1] != '\0') {
		config_line_r->value = "Garbage after '{'";
		config_line_r->type = CONFIG_LINE_TYPE_ERROR;
		return;
	}
	config_line_r->type = CONFIG_LINE_TYPE_SECTION_BEGIN;
}

static int
config_parse_finish(struct config_parser_context *ctx,
		    enum config_parse_flags flags,
		    struct config_parsed **config_r, const char **error_r)
{
	struct config_parsed *new_config;
	const char *error;
	int ret = 0;

	if (hook_config_parser_end != NULL)
		ret = hook_config_parser_end(ctx, error_r);

	new_config = p_new(ctx->pool, struct config_parsed, 1);
	new_config->pool = ctx->pool;
	pool_ref(new_config->pool);
	p_array_init(&new_config->errors, ctx->pool, 1);

	array_append_zero(&ctx->all_filter_parsers);
	new_config->filter_parsers = array_front(&ctx->all_filter_parsers);
	new_config->module_parsers = ctx->root_module_parsers;

	if (ret < 0)
		;
	else if ((ret = config_all_parsers_check(ctx, new_config, &error)) < 0) {
		*error_r = t_strdup_printf("Error in configuration file %s: %s",
					   ctx->path, error);
	}

	if (ret < 0 && (flags & CONFIG_PARSE_FLAG_RETURN_BROKEN_CONFIG) == 0) {
		config_parsed_free(&new_config);
		return -1;
	}
	*config_r = new_config;
	return ret;
}

static const void *
config_get_value(struct config_section_stack *section,
		 struct config_parser_key *config_key, const char *key,
		 bool expand_parent, enum setting_type *type_r)
{
	struct config_module_parser *l =
		&section->module_parsers[config_key->info_idx];
	const void *value;

	if (l->parser != NULL) {
		value = settings_parse_get_value(l->parser, &key, type_r);
		i_assert(value != NULL);

		if (!expand_parent || section->prev == NULL ||
		    settings_parse_get_change_counter(l->parser, key) != 0)
			return value;
	}

	/* not changed by this parser. maybe parent has. */
	return config_get_value(section->prev, config_key, key, TRUE, type_r);
}

static int config_write_keyvariable(struct config_parser_context *ctx,
				    const char *key, const char *value,
				    string_t *str)
{
	const char *var_end, *p_start = value;
	bool dump;
	while (value != NULL) {
		const char *var_name, *env_name;
		bool expand_parent;
		var_end = strchr(value, ' ');

		/* expand_parent=TRUE for "key = $key stuff".
		   we'll always expand it so that doveconf -n can give
		   usable output */
		if (var_end == NULL)
			var_name = value;
		else
			var_name = t_strdup_until(value, var_end);
		expand_parent = strcmp(key, var_name +
				       (*var_name == '$' ? 1 : 0)) == 0;

		if (!str_begins_with(var_name, "$") ||
		    (value > p_start && !IS_WHITE(value[-1]))) {
			str_append(str, var_name);
		} else if (!ctx->expand_values && !expand_parent) {
			str_append(str, var_name);
		} else if (str_begins(var_name, "$ENV:", &env_name)) {
			/* use environment variable */
			const char *envval = getenv(env_name);
			if (envval != NULL)
				str_append(str, envval);
		} else {
			struct config_parser_key *config_key;
			const char *var_value;
			enum setting_type var_type;

			i_assert(var_name[0] == '$');
			var_name++;

			config_key = hash_table_lookup(ctx->all_keys, var_name);
			var_value = config_key == NULL ? NULL :
				config_get_value(ctx->cur_section, config_key,
						 var_name, expand_parent, &var_type);
			if (var_value == NULL) {
				ctx->error = p_strconcat(ctx->pool,
							 "Unknown variable: $",
							 var_name, NULL);
				return -1;
			}
			if (!config_export_type(str, var_value, NULL,
						var_type, TRUE, &dump)) {
				ctx->error = p_strconcat(ctx->pool,
							 "Invalid variable: $",
							 var_name, NULL);
				return -1;
			}
		}

		if (var_end == NULL)
			break;

		str_append_c(str, ' ');

		/* find next token */
		while (*var_end != '\0' && IS_WHITE(*var_end)) var_end++;
		value = var_end;
		while (*var_end != '\0' && !IS_WHITE(*var_end)) var_end++;
	}

	return 0;
}

static int config_write_value(struct config_parser_context *ctx,
			      const struct config_line *line)
{
	const char *error, *path, *key_with_path;

	str_truncate(ctx->value, 0);
	switch (line->type) {
	case CONFIG_LINE_TYPE_KEYVALUE:
		str_append(ctx->value, line->value);
		break;
	case CONFIG_LINE_TYPE_KEYFILE:
		if (!ctx->expand_values) {
			str_append_c(ctx->value, '<');
			str_append(ctx->value, line->value);
		} else {
			key_with_path = t_strconcat(str_c(ctx->key_path),
						    line->key, NULL);
			path = fix_relative_path(line->value, ctx->cur_input);
			if (str_append_file(ctx->value, key_with_path, path,
					    &error) < 0) {
				/* file reading failed */
				ctx->error = p_strdup(ctx->pool, error);
				return -1;
			}
		}
		break;
	case CONFIG_LINE_TYPE_KEYVARIABLE:
		if (config_write_keyvariable(ctx, line->key, line->value,
					     ctx->value) < 0)
			return -1;
		break;
	default:
		i_unreached();
	}
	return 0;
}

static void
config_parser_check_warnings(struct config_parser_context *ctx, const char *key)
{
	const char *path, *first_pos;

	if (ctx->cur_input == NULL) {
		/* coming from old_settings_handle_post() - we don't need to
		   track seen settings in there. */
		return;
	}

	first_pos = hash_table_lookup(ctx->seen_settings, key);
	if (ctx->cur_section->prev == NULL) {
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
	first_pos = p_strdup_printf(ctx->pool, "%s line %u",
				    ctx->cur_input->path, ctx->cur_input->linenum);
	path = p_strdup(ctx->pool, key);
	hash_table_insert(ctx->seen_settings, path, first_pos);
}

void config_parser_apply_line(struct config_parser_context *ctx,
			      const struct config_line *line)
{
	const char *full_key;

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
			if (!ctx->delay_errors ||
			    config_apply_error(ctx, line->key) < 0)
				break;
		} else {
			const char *key_with_path = t_strdup_printf("%s%s",
				str_c(ctx->key_path), line->key);
			if (config_apply_line(ctx, key_with_path,
					      str_c(ctx->value), &full_key) == 0)
				config_parser_check_warnings(ctx, full_key);
		}
		break;
	case CONFIG_LINE_TYPE_SECTION_BEGIN:
		ctx->cur_section = config_add_new_section(ctx);
		ctx->cur_section->pathlen = str_len(ctx->key_path);
		ctx->cur_section->key = p_strdup(ctx->pool, line->key);

		if (config_filter_add_new_filter(ctx, line)) {
			/* new filter */
			break;
		}

		/* This is SET_STRLIST */
		str_append(ctx->key_path, line->key);
		str_append_c(ctx->key_path, SETTINGS_SEPARATOR);
		break;
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
			str_truncate(ctx->key_path, ctx->cur_section->pathlen);
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

	for (unsigned int i = 0; info->defines[i].key != NULL; i++) {
		const struct setting_define *def = &info->defines[i];
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
}

int config_parse_file(const char *path, enum config_parse_flags flags,
		      struct config_parsed **config_r,
		      const char **error_r)
{
	struct input_stack root;
	struct config_parser_context ctx;
	unsigned int i, count;
	string_t *full_line;
	char *line;
	int fd, ret = 0;
	bool handled;

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
	ctx.hide_obsolete_warnings =
		(flags & CONFIG_PARSE_FLAG_HIDE_OBSOLETE_WARNINGS) != 0;
	ctx.delay_errors = (flags & CONFIG_PARSE_FLAG_DELAY_ERRORS) != 0;
	hash_table_create(&ctx.all_keys, ctx.pool, 500, str_hash, strcmp);

	for (count = 0; all_infos[count] != NULL; count++) ;
	ctx.root_module_parsers =
		p_new(ctx.pool, struct config_module_parser, count+1);
	unsigned int service_info_idx = UINT_MAX;
	for (i = 0; i < count; i++) {
		if (strcmp(all_infos[i]->name, "service") == 0)
			service_info_idx = i;
		ctx.root_module_parsers[i].info = all_infos[i];
		ctx.root_module_parsers[i].parser =
			settings_parser_init(ctx.pool, all_infos[i],
					     settings_parser_flags);
		settings_parse_set_change_counter(ctx.root_module_parsers[i].parser,
						  CONFIG_PARSER_CHANGE_EXPLICIT);
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
	root.path = path;
	ctx.cur_input = &root;
	ctx.expand_values = (flags & CONFIG_PARSE_FLAG_EXPAND_VALUES) != 0;
	hash_table_create(&ctx.seen_settings, ctx.pool, 0, str_hash, strcmp);

	p_array_init(&ctx.all_filter_parsers, ctx.pool, 128);
	ctx.cur_section = p_new(ctx.pool, struct config_section_stack, 1);
	config_add_new_parser(&ctx, ctx.cur_section);

	ctx.key_path = str_new(ctx.pool, 256);
	ctx.value = str_new(ctx.pool, 256);
	full_line = str_new(default_pool, 512);
	ctx.cur_input->input = fd != -1 ?
		i_stream_create_fd_autoclose(&fd, SIZE_MAX) :
		i_stream_create_from_data("", 0);
	i_stream_set_return_partial_line(ctx.cur_input->input, TRUE);
	old_settings_init(&ctx);
	if ((flags & CONFIG_PARSE_FLAG_NO_DEFAULTS) == 0)
		config_parser_add_services(&ctx, service_info_idx);
	if (hook_config_parser_begin != NULL) T_BEGIN {
		hook_config_parser_begin(&ctx);
	} T_END;

prevfile:
	while ((line = i_stream_read_next_line(ctx.cur_input->input)) != NULL) {
		struct config_line config_line;
		ctx.cur_input->linenum++;
		config_parse_line(&ctx, line, full_line, &config_line);
		if (config_line.type == CONFIG_LINE_TYPE_CONTINUE)
			continue;

		T_BEGIN {
			handled = old_settings_handle(&ctx, &config_line);
			if (!handled)
				config_parser_apply_line(&ctx, &config_line);
		} T_END;

		if (ctx.error != NULL) {
			*error_r = t_strdup_printf(
				"Error in configuration file %s line %d: %s",
				ctx.cur_input->path, ctx.cur_input->linenum,
				ctx.error);
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

	old_settings_handle_post(&ctx);
	hash_table_destroy(&ctx.seen_settings);
	hash_table_destroy(&ctx.all_keys);
	str_free(&full_line);
	if (ret == 0)
		ret = config_parse_finish(&ctx, flags, config_r, error_r);
	else {
		struct config_filter_parser *filter_parser;
		array_foreach_elem(&ctx.all_filter_parsers, filter_parser)
			config_module_parsers_free(filter_parser->module_parsers);
		config_module_parsers_free(ctx.root_module_parsers);
	}
	pool_unref(&ctx.pool);
	return ret < 0 ? ret : 1;
}

const ARRAY_TYPE(const_string) *
config_parsed_get_errors(struct config_parsed *config)
{
	return &config->errors;
}

struct config_filter_parser *
config_parsed_get_global_filter_parser(struct config_parsed *config)
{
	return config->filter_parsers[0];
}

struct config_filter_parser *const *
config_parsed_get_filter_parsers(struct config_parsed *config)
{
	return config->filter_parsers;
}

const struct config_module_parser *
config_parsed_get_module_parsers(struct config_parsed *config)
{
	return config->module_parsers;
}

const char *
config_module_parsers_get_setting(const struct config_module_parser *module_parsers,
				  const char *info_name, const char *key)
{
	const struct config_module_parser *l;

	for (l = module_parsers; l->info != NULL; l++) {
		if (strcmp(l->info->name, info_name) != 0)
			continue;

		enum setting_type type;
		const char *const *value =
			settings_parse_get_value(l->parser, &key, &type);
		if (value != NULL) {
			i_assert(type == SET_STR || type == SET_STR_VARS);
			return *value;
		}
	}
	i_panic("BUG: Couldn't find setting with info=%s key=%s",
		info_name, key);
}

void config_parsed_free(struct config_parsed **_config)
{
	struct config_parsed *config = *_config;
	unsigned int i;

	if (config == NULL)
		return;
	*_config = NULL;

	for (i = 0; config->filter_parsers[i] != NULL; i++)
		config_module_parsers_free(config->filter_parsers[i]->module_parsers);
	config_module_parsers_free(config->module_parsers);
	pool_unref(&config->pool);
}

void config_module_parsers_free(struct config_module_parser *parsers)
{
	unsigned int i;

	for (i = 0; parsers[i].info != NULL; i++)
		settings_parser_unref(&parsers[i].parser);
}

static int config_service_cmp(const struct config_service *s1,
			      const struct config_service *s2)
{
	return strcmp(s1->set->name, s2->set->name);
}

void config_parse_load_modules(void)
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
	modules = module_dir_load(CONFIG_MODULE_DIR, NULL, &mod_set);
	module_dir_init(modules);

	i_array_init(&new_infos, 64);
	i_array_init(&new_services, 64);
	for (m = modules; m != NULL; m = m->next) {
		infos = module_get_symbol_quiet(m,
			t_strdup_printf("%s_set_infos", m->name));
		if (infos != NULL) {
			for (i = 0; infos[i] != NULL; i++)
				array_push_back(&new_infos, &infos[i]);
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
	if (array_count(&new_infos) > 0) {
		/* modules added new settings. add the defaults and start
		   using the new list. */
		for (i = 0; all_infos[i] != NULL; i++)
			array_push_back(&new_infos, &all_infos[i]);
		array_append_zero(&new_infos);
		all_infos = array_front(&new_infos);
		infos_free_at_deinit = new_infos;
	} else {
		array_free(&new_infos);
	}
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
}

void config_parser_deinit(void)
{
	if (array_is_created(&services_free_at_deinit))
		array_free(&services_free_at_deinit);
	if (array_is_created(&infos_free_at_deinit))
		array_free(&infos_free_at_deinit);
}
