/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "hash.h"
#include "strescape.h"
#include "istream.h"
#include "module-dir.h"
#include "settings-parser.h"
#include "service-settings.h"
#include "master-service.h"
#include "master-service-settings.h"
#include "master-service-ssl-settings.h"
#include "all-settings.h"
#include "old-set-parser.h"
#include "config-request.h"
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

ARRAY_DEFINE_TYPE(setting_parser_info_p, const struct setting_parser_info *);

static const enum settings_parser_flags settings_parser_flags =
	SETTINGS_PARSER_FLAG_IGNORE_UNKNOWN_KEYS |
	SETTINGS_PARSER_FLAG_TRACK_CHANGES;

struct config_module_parser *config_module_parsers;
struct config_filter_context *config_filter;
struct module *modules;
void (*hook_config_parser_begin)(struct config_parser_context *ctx);
int (*hook_config_parser_end)(struct config_parser_context *ctx,
			      const char **error_r);

static ARRAY_TYPE(service_settings) services_free_at_deinit = ARRAY_INIT;
static ARRAY_TYPE(setting_parser_info_p) roots_free_at_deinit = ARRAY_INIT;

static const char *info_type_name_find(const struct setting_parser_info *info)
{
	unsigned int i;

	for (i = 0; info->defines[i].key != NULL; i++) {
		if (info->defines[i].offset == info->type_offset)
			return info->defines[i].key;
	}
	i_panic("setting parser: Invalid type_offset value");
	return NULL;
}

static int config_add_type(struct setting_parser_context *parser,
			   const char *line, const char *section_name)
{
	const struct setting_parser_info *info;
	const char *p;
	string_t *str;
	int ret;

	info = settings_parse_get_prev_info(parser);
	if (info == NULL) {
		/* section inside strlist */
		return -1;
	}
	if (info->type_offset == (size_t)-1)
		return 0;

	str = t_str_new(256);
	p = strchr(line, '=');
	str_append_data(str, line, p-line);
	str_append_c(str, SETTINGS_SEPARATOR);
	str_append(str, p+1);
	if (info != NULL) {
		str_append_c(str, SETTINGS_SEPARATOR);
		str_append(str, info_type_name_find(info));
	}

	ret = settings_parse_keyvalue(parser, str_c(str), section_name);
	i_assert(ret > 0);
	return 0;
}

static bool
config_parser_is_in_localremote(struct config_section_stack *section)
{
	const struct config_filter *filter = &section->filter;

	return filter->local_name != NULL || filter->local_bits > 0 ||
		filter->remote_bits > 0;
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

int config_apply_line(struct config_parser_context *ctx, const char *key,
		      const char *line, const char *section_name)
{
	struct config_module_parser *l;
	bool found = FALSE;
	int ret;

	for (l = ctx->cur_section->parsers; l->root != NULL; l++) {
		ret = settings_parse_line(l->parser, line);
		if (ret > 0) {
			found = TRUE;
			/* FIXME: remove once auth does support these. */
			if (strcmp(l->root->module_name, "auth") == 0 &&
			    config_parser_is_in_localremote(ctx->cur_section)) {
				ctx->error = p_strconcat(ctx->pool,
					"Auth settings not supported inside local/remote blocks: ",
					key, NULL);
				return -1;
			}
			if (section_name != NULL) {
				if (config_add_type(l->parser, line, section_name) < 0) {
					ctx->error = "Section not allowed here";
					return -1;
				}
			}
		} else if (ret < 0) {
			ctx->error = settings_parser_get_error(l->parser);
			return -1;
		}
	}
	if (!found) {
		ctx->error = p_strconcat(ctx->pool, "Unknown setting: ",
					 get_setting_full_path(ctx, key), NULL);
		return -1;
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

	for (count = 0; all_roots[count] != NULL; count++) ;

	dest = p_new(pool, struct config_module_parser, count + 1);
	for (i = 0; i < count; i++) {
		dest[i].root = all_roots[i];
		dest[i].parser = settings_parser_init(pool, all_roots[i],
						      settings_parser_flags);
	}
	return dest;
}

static void
config_add_new_parser(struct config_parser_context *ctx)
{
	struct config_section_stack *cur_section = ctx->cur_section;
	struct config_filter_parser *parser;

	parser = p_new(ctx->pool, struct config_filter_parser, 1);
	parser->filter = cur_section->filter;
	if (ctx->cur_input->linenum == 0) {
		parser->file_and_line =
			p_strdup(ctx->pool, ctx->cur_input->path);
	} else {
		parser->file_and_line =
			p_strdup_printf(ctx->pool, "%s:%d",
					ctx->cur_input->path,
					ctx->cur_input->linenum);
	}
	parser->parsers = cur_section->prev == NULL ? ctx->root_parsers :
		config_module_parsers_init(ctx->pool);
	array_append(&ctx->all_parsers, &parser, 1);

	cur_section->parsers = parser->parsers;
}

static struct config_section_stack *
config_add_new_section(struct config_parser_context *ctx)
{
	struct config_section_stack *section;

	section = p_new(ctx->pool, struct config_section_stack, 1);
	section->prev = ctx->cur_section;
	section->filter = ctx->cur_section->filter;
	section->parsers = ctx->cur_section->parsers;

	section->open_path = p_strdup(ctx->pool, ctx->cur_input->path);
	section->open_linenum = ctx->cur_input->linenum;
	return section;
}

static struct config_filter_parser *
config_filter_parser_find(struct config_parser_context *ctx,
			  const struct config_filter *filter)
{
	struct config_filter_parser *const *parsers;

	array_foreach(&ctx->all_parsers, parsers) {
		struct config_filter_parser *parser = *parsers;

		if (config_filters_equal(&parser->filter, filter))
			return parser;
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
			     const char *key, const char *value)
{
	struct config_filter *filter = &ctx->cur_section->filter;
	struct config_filter *parent = &ctx->cur_section->prev->filter;
	struct config_filter_parser *parser;
	const char *error;

	if (strcmp(key, "protocol") == 0) {
		if (parent->service != NULL)
			ctx->error = "Nested protocol { protocol { .. } } block not allowed";
		else
			filter->service = p_strdup(ctx->pool, value);
	} else if (strcmp(key, "local") == 0) {
		if (parent->remote_bits > 0)
			ctx->error = "remote { local { .. } } not allowed (use local { remote { .. } } instead)";
		else if (parent->service != NULL)
			ctx->error = "protocol { local { .. } } not allowed (use local { protocol { .. } } instead)";
		else if (parent->local_name != NULL)
			ctx->error = "local_name { local { .. } } not allowed (use local { local_name { .. } } instead)";
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
		else
			filter->local_name = p_strdup(ctx->pool, value);
	} else if (strcmp(key, "remote") == 0) {
		if (parent->service != NULL)
			ctx->error = "protocol { remote { .. } } not allowed (use remote { protocol { .. } } instead)";
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
	} else {
		return FALSE;
	}

	parser = config_filter_parser_find(ctx, filter);
	if (parser != NULL)
		ctx->cur_section->parsers = parser->parsers;
	else
		config_add_new_parser(ctx);
	ctx->cur_section->is_filter = TRUE;
	return TRUE;
}

static int
config_filter_parser_check(struct config_parser_context *ctx,
			   const struct config_module_parser *p,
			   const char **error_r)
{
	const char *error;
	char *error_dup = NULL;
	bool ok;

	for (; p->root != NULL; p++) {
		/* skip checking settings we don't care about */
		if (!config_module_want_parser(ctx->root_parsers,
					       ctx->modules, p->root))
			continue;

		settings_parse_var_skip(p->parser);
		T_BEGIN {
			ok = settings_parser_check(p->parser, ctx->pool, &error);
			if (!ok)
				error_dup = i_strdup(error);
		} T_END;
		if (!ok) {
			i_assert(error_dup != NULL);
			*error_r = t_strdup(error_dup);
			i_free(error_dup);
			return -1;
		}
	}
	return 0;
}

static const char *
get_str_setting(struct config_filter_parser *parser, const char *key,
		const char *default_value)
{
	struct config_module_parser *module_parser;
	const char *const *set_value;
	enum setting_type set_type;

	module_parser = parser->parsers;
	for (; module_parser->parser != NULL; module_parser++) {
		set_value = settings_parse_get_value(module_parser->parser,
						     key, &set_type);
		if (set_value != NULL &&
		    settings_parse_is_changed(module_parser->parser, key)) {
			i_assert(set_type == SET_STR || set_type == SET_ENUM);
			return *set_value;
		}
	}
	return default_value;
}

static int
config_all_parsers_check(struct config_parser_context *ctx,
			 struct config_filter_context *new_filter,
			 const char **error_r)
{
	struct config_filter_parser *const *parsers;
	struct config_module_parser *tmp_parsers;
	struct master_service_settings_output output;
	unsigned int i, count;
	const char *ssl_set, *global_ssl_set;
	pool_t tmp_pool;
	bool ssl_warned = FALSE;
	int ret = 0;

	if (ctx->cur_section->prev != NULL) {
		*error_r = t_strdup_printf(
			"Missing '}' (section started at %s:%u)",
			ctx->cur_section->open_path,
			ctx->cur_section->open_linenum);
		return -1;
	}

	tmp_pool = pool_alloconly_create(MEMPOOL_GROWING"config parsers check", 1024*64);
	parsers = array_get(&ctx->all_parsers, &count);
	i_assert(count > 0 && parsers[count-1] == NULL);
	count--;

	global_ssl_set = get_str_setting(parsers[0], "ssl", "");
	for (i = 0; i < count && ret == 0; i++) {
		if (config_filter_parsers_get(new_filter, tmp_pool, NULL,
					      &parsers[i]->filter,
					      &tmp_parsers, &output,
					      error_r) < 0) {
			ret = -1;
			break;
		}

		ssl_set = get_str_setting(parsers[i], "ssl", global_ssl_set);
		if (strcmp(ssl_set, "no") != 0 &&
		    strcmp(global_ssl_set, "no") == 0 && !ssl_warned) {
			i_warning("SSL is disabled because global ssl=no, "
				  "ignoring ssl=%s for subsection", ssl_set);
			ssl_warned = TRUE;
		}

		ret = config_filter_parser_check(ctx, tmp_parsers, error_r);
		config_filter_parsers_free(tmp_parsers);
		p_clear(tmp_pool);
	}
	pool_unref(&tmp_pool);
	return ret;
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
	new_input->input = i_stream_create_fd_autoclose(&fd, (size_t)-1);
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

static enum config_line_type
config_parse_line(struct config_parser_context *ctx,
		  char *line, string_t *full_line,
		  const char **key_r, const char **value_r)
{
	const char *key;
	size_t len;
	char *p;

	*key_r = NULL;
	*value_r = NULL;

	/* @UNSAFE: line is modified */

	/* skip whitespace */
	while (IS_WHITE(*line))
		line++;

	/* ignore comments or empty lines */
	if (*line == '#' || *line == '\0')
		return CONFIG_LINE_TYPE_SKIP;

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
		return CONFIG_LINE_TYPE_CONTINUE;
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
	*key_r = key;
	*value_r = line;

	if (strcmp(key, "!include") == 0)
		return CONFIG_LINE_TYPE_INCLUDE;
	if (strcmp(key, "!include_try") == 0)
		return CONFIG_LINE_TYPE_INCLUDE_TRY;

	if (*line == '=') {
		/* a) */
		*line++ = '\0';
		while (IS_WHITE(*line)) line++;

		if (*line == '<') {
			while (IS_WHITE(line[1])) line++;
			*value_r = line + 1;
			return CONFIG_LINE_TYPE_KEYFILE;
		}
		if (*line == '$') {
			*value_r = line + 1;
			return CONFIG_LINE_TYPE_KEYVARIABLE;
		}

		len = strlen(line);
		if (len > 0 &&
		    ((*line == '"' && line[len-1] == '"') ||
		     (*line == '\'' && line[len-1] == '\''))) {
			line[len-1] = '\0';
			line = str_unescape(line+1);
		}
		*value_r = line;
		return CONFIG_LINE_TYPE_KEYVALUE;
	}

	if (strcmp(key, "}") == 0 && *line == '\0')
		return CONFIG_LINE_TYPE_SECTION_END;

	/* b) + errors */
	line[-1] = '\0';

	if (*line == '{')
		*value_r = "";
	else {
		/* get section name */
		if (*line != '"') {
			*value_r = line;
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
				*value_r = str_unescape(value);
			}
		}
		if (*line != '{') {
			*value_r = "Expecting '{'";
			return CONFIG_LINE_TYPE_ERROR;
		}
	}
	if (line[1] != '\0') {
		*value_r = "Garbage after '{'";
		return CONFIG_LINE_TYPE_ERROR;
	}
	return CONFIG_LINE_TYPE_SECTION_BEGIN;
}

static int config_parse_finish(struct config_parser_context *ctx, const char **error_r)
{
	struct config_filter_context *new_filter;
	const char *error;
	int ret = 0;

	if (hook_config_parser_end != NULL)
		ret = hook_config_parser_end(ctx, error_r);

	new_filter = config_filter_init(ctx->pool);
	array_append_zero(&ctx->all_parsers);
	config_filter_add_all(new_filter, array_idx(&ctx->all_parsers, 0));

	if (ret < 0)
		;
	else if (ctx->hide_errors)
		ret = 0;
	else if ((ret = config_all_parsers_check(ctx, new_filter, &error)) < 0) {
		*error_r = t_strdup_printf("Error in configuration file %s: %s",
					   ctx->path, error);
	}

	if (config_filter != NULL)
		config_filter_deinit(&config_filter);
	config_module_parsers = ctx->root_parsers;
	config_filter = new_filter;
	return ret;
}

static const void *
config_get_value(struct config_section_stack *section, const char *key,
		 bool expand_parent, enum setting_type *type_r)
{
	struct config_module_parser *l;
	const void *value;

	for (l = section->parsers; l->root != NULL; l++) {
		value = settings_parse_get_value(l->parser, key, type_r);
		if (value != NULL) {
			if (!expand_parent || section->prev == NULL ||
			    settings_parse_is_changed(l->parser, key))
				return value;

			/* not changed by this parser. maybe parent has. */
			return config_get_value(section->prev,
						key, TRUE, type_r);
		}
	}
	return NULL;
}

static bool
config_require_key(struct config_parser_context *ctx, const char *key)
{
	struct config_module_parser *l;

	if (ctx->modules == NULL)
		return TRUE;

	for (l = ctx->cur_section->parsers; l->root != NULL; l++) {
		if (config_module_want_parser(ctx->root_parsers,
					      ctx->modules, l->root) &&
		    settings_parse_is_valid_key(l->parser, key))
			return TRUE;
	}
	return FALSE;
}

static int config_write_value(struct config_parser_context *ctx,
			      enum config_line_type type,
			      const char *key, const char *value)
{
	string_t *str = ctx->str;
	const void *var_name, *var_value, *p;
	enum setting_type var_type;
	const char *error, *path, *full_key;
	bool dump, expand_parent;

	switch (type) {
	case CONFIG_LINE_TYPE_KEYVALUE:
		str_append(str, value);
		break;
	case CONFIG_LINE_TYPE_KEYFILE:
		full_key = t_strndup(str_data(ctx->str), str_len(str)-1);
		if (!ctx->expand_values) {
			str_append_c(str, '<');
			str_append(str, value);
		} else {
			if (!config_require_key(ctx, full_key)) {
				/* don't even try to open the file */
			} else {
				path = fix_relative_path(value, ctx->cur_input);
				if (str_append_file(str, full_key, path, &error) < 0) {
					/* file reading failed */
					ctx->error = p_strdup(ctx->pool, error);
					return -1;
				}
			}
		}
		break;
	case CONFIG_LINE_TYPE_KEYVARIABLE:
		/* expand_parent=TRUE for "key = $key stuff".
		   we'll always expand it so that doveconf -n can give
		   usable output */
		p = strchr(value, ' ');
		if (p == NULL)
			var_name = value;
		else
			var_name = t_strdup_until(value, p);
		expand_parent = strcmp(key, var_name) == 0;

		if (!ctx->expand_values && !expand_parent) {
			str_append_c(str, '$');
			str_append(str, value);
		} else {
			var_value = config_get_value(ctx->cur_section, var_name,
						     expand_parent, &var_type);
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
			if (p != NULL)
				str_append(str, p);
		}
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

	first_pos = hash_table_lookup(ctx->seen_settings, str_c(ctx->str));
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
	path = p_strdup(ctx->pool, str_c(ctx->str));
	hash_table_insert(ctx->seen_settings, path, first_pos);
}

void config_parser_apply_line(struct config_parser_context *ctx,
			      enum config_line_type type,
			      const char *key, const char *value)
{
	const char *section_name;

	str_truncate(ctx->str, ctx->pathlen);
	switch (type) {
	case CONFIG_LINE_TYPE_SKIP:
		break;
	case CONFIG_LINE_TYPE_CONTINUE:
		i_unreached();
	case CONFIG_LINE_TYPE_ERROR:
		ctx->error = p_strdup(ctx->pool, value);
		break;
	case CONFIG_LINE_TYPE_KEYVALUE:
	case CONFIG_LINE_TYPE_KEYFILE:
	case CONFIG_LINE_TYPE_KEYVARIABLE:
		str_append(ctx->str, key);
		config_parser_check_warnings(ctx, key);
		str_append_c(ctx->str, '=');

		if (config_write_value(ctx, type, key, value) < 0)
			break;
		(void)config_apply_line(ctx, key, str_c(ctx->str), NULL);
		break;
	case CONFIG_LINE_TYPE_SECTION_BEGIN:
		ctx->cur_section = config_add_new_section(ctx);
		ctx->cur_section->pathlen = ctx->pathlen;
		ctx->cur_section->key = p_strdup(ctx->pool, key);

		if (config_filter_add_new_filter(ctx, key, value)) {
			/* new filter */
			break;
		}

		/* new config section */
		if (*value == '\0') {
			/* no section name, use a counter */
			section_name = dec2str(ctx->section_counter++);
		} else {
			section_name = settings_section_escape(value);
		}
		str_append(ctx->str, key);
		ctx->pathlen = str_len(ctx->str);

		str_append_c(ctx->str, '=');
		str_append(ctx->str, section_name);

		if (config_apply_line(ctx, key, str_c(ctx->str), value) < 0)
			break;

		str_truncate(ctx->str, ctx->pathlen);
		str_append_c(ctx->str, SETTINGS_SEPARATOR);
		str_append(ctx->str, section_name);
		str_append_c(ctx->str, SETTINGS_SEPARATOR);
		ctx->pathlen = str_len(ctx->str);
		break;
	case CONFIG_LINE_TYPE_SECTION_END:
		if (ctx->cur_section->prev == NULL)
			ctx->error = "Unexpected '}'";
		else {
			ctx->pathlen = ctx->cur_section->pathlen;
			ctx->cur_section = ctx->cur_section->prev;
		}
		break;
	case CONFIG_LINE_TYPE_INCLUDE:
	case CONFIG_LINE_TYPE_INCLUDE_TRY:
		(void)settings_include(ctx, fix_relative_path(value, ctx->cur_input),
				       type == CONFIG_LINE_TYPE_INCLUDE_TRY);
		break;
	}
}

int config_parse_file(const char *path, bool expand_values,
		      const char *const *modules, const char **error_r)
{
	struct input_stack root;
	struct config_parser_context ctx;
	unsigned int i, count;
	const char *key, *value;
	string_t *full_line;
	enum config_line_type type;
	char *line;
	int fd, ret = 0;
	bool handled;

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
	ctx.hide_errors = fd == -1;

	for (count = 0; all_roots[count] != NULL; count++) ;
	ctx.root_parsers =
		p_new(ctx.pool, struct config_module_parser, count+1);
	for (i = 0; i < count; i++) {
		ctx.root_parsers[i].root = all_roots[i];
		ctx.root_parsers[i].parser =
			settings_parser_init(ctx.pool, all_roots[i],
					     settings_parser_flags);
	}

	i_zero(&root);
	root.path = path;
	ctx.cur_input = &root;
	ctx.expand_values = expand_values;
	ctx.modules = modules;
	hash_table_create(&ctx.seen_settings, ctx.pool, 0, str_hash, strcmp);

	p_array_init(&ctx.all_parsers, ctx.pool, 128);
	ctx.cur_section = p_new(ctx.pool, struct config_section_stack, 1);
	config_add_new_parser(&ctx);

	ctx.str = str_new(ctx.pool, 256);
	full_line = str_new(default_pool, 512);
	ctx.cur_input->input = fd != -1 ?
		i_stream_create_fd_autoclose(&fd, (size_t)-1) :
		i_stream_create_from_data("", 0);
	i_stream_set_return_partial_line(ctx.cur_input->input, TRUE);
	old_settings_init(&ctx);
	if (hook_config_parser_begin != NULL) T_BEGIN {
		hook_config_parser_begin(&ctx);
	} T_END;

prevfile:
	while ((line = i_stream_read_next_line(ctx.cur_input->input)) != NULL) {
		ctx.cur_input->linenum++;
		type = config_parse_line(&ctx, line, full_line,
					 &key, &value);
		str_truncate(ctx.str, ctx.pathlen);
		if (type == CONFIG_LINE_TYPE_CONTINUE)
			continue;

		T_BEGIN {
			handled = old_settings_handle(&ctx, type, key, value);
			if (!handled)
				config_parser_apply_line(&ctx, type, key, value);
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

	hash_table_destroy(&ctx.seen_settings);
	str_free(&full_line);
	if (ret == 0)
		ret = config_parse_finish(&ctx, error_r);
	return ret < 0 ? ret : 1;
}

void config_parse_load_modules(void)
{
	struct module_dir_load_settings mod_set;
	struct module *m;
	const struct setting_parser_info **roots;
	ARRAY_TYPE(setting_parser_info_p) new_roots;
	ARRAY_TYPE(service_settings) new_services;
	struct service_settings *const *services, *service_set;
	unsigned int i, count;

	i_zero(&mod_set);
	mod_set.abi_version = DOVECOT_ABI_VERSION;
	modules = module_dir_load(CONFIG_MODULE_DIR, NULL, &mod_set);
	module_dir_init(modules);

	i_array_init(&new_roots, 64);
	i_array_init(&new_services, 64);
	for (m = modules; m != NULL; m = m->next) {
		roots = module_get_symbol_quiet(m,
			t_strdup_printf("%s_set_roots", m->name));
		if (roots != NULL) {
			for (i = 0; roots[i] != NULL; i++)
				array_append(&new_roots, &roots[i], 1);
		}

		services = module_get_symbol_quiet(m,
			t_strdup_printf("%s_service_settings_array", m->name));
		if (services != NULL) {
			for (count = 0; services[count] != NULL; count++) ;
			array_append(&new_services, services, count);
		} else {
			service_set = module_get_symbol_quiet(m,
				t_strdup_printf("%s_service_settings", m->name));
			if (service_set != NULL)
				array_append(&new_services, &service_set, 1);
		}
	}
	if (array_count(&new_roots) > 0) {
		/* modules added new settings. add the defaults and start
		   using the new list. */
		for (i = 0; all_roots[i] != NULL; i++)
			array_append(&new_roots, &all_roots[i], 1);
		array_append_zero(&new_roots);
		all_roots = array_idx(&new_roots, 0);
		roots_free_at_deinit = new_roots;
	} else {
		array_free(&new_roots);
	}
	if (array_count(&new_services) > 0) {
		/* module added new services. update the defaults. */
		services = array_get(default_services, &count);
		for (i = 0; i < count; i++)
			array_append(&new_services, &services[i], 1);
		*default_services = new_services;
		services_free_at_deinit = new_services;
	} else {
		array_free(&new_services);
	}
}

static bool parsers_are_connected(const struct setting_parser_info *root,
				  const struct setting_parser_info *info)
{
	const struct setting_parser_info *p;
	const struct setting_parser_info *const *dep;

	/* we're trying to find info or its parents from root's dependencies. */

	for (p = info; p != NULL; p = p->parent) {
		if (p == root)
			return TRUE;
	}

	if (root->dependencies != NULL) {
		for (dep = root->dependencies; *dep != NULL; dep++) {
			if (parsers_are_connected(*dep, info))
				return TRUE;
		}
	}
	return FALSE;
}

bool config_module_want_parser(struct config_module_parser *parsers,
			       const char *const *modules,
			       const struct setting_parser_info *root)
{
	struct config_module_parser *l;

	if (modules == NULL)
		return TRUE;
	if (root == &master_service_setting_parser_info) {
		/* everyone wants master service settings */
		return TRUE;
	}

	for (l = parsers; l->root != NULL; l++) {
		if (!str_array_find(modules, l->root->module_name))
			continue;

		/* see if we can find a way to get from the original parser
		   to this parser */
		if (parsers_are_connected(l->root, root))
			return TRUE;
	}
	return FALSE;
}

void config_parser_deinit(void)
{
	if (array_is_created(&services_free_at_deinit))
		array_free(&services_free_at_deinit);
	if (array_is_created(&roots_free_at_deinit))
		array_free(&roots_free_at_deinit);
}
