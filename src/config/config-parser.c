/* Copyright (C) 2005-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "hash.h"
#include "strescape.h"
#include "istream.h"
#include "module-dir.h"
#include "settings-parser.h"
#include "all-settings.h"
#include "config-filter.h"
#include "config-parser.h"

#include <unistd.h>
#include <fcntl.h>
#ifdef HAVE_GLOB_H
#  include <glob.h>
#endif

#ifndef GLOB_BRACE
#  define GLOB_BRACE 0
#endif

#define IS_WHITE(c) ((c) == ' ' || (c) == '\t')

struct config_section_stack {
	struct config_section_stack *prev;

	struct config_filter filter;
	/* root=NULL-terminated list of parsers */
	struct config_module_parser *parsers;
	unsigned int pathlen;
};

struct input_stack {
	struct input_stack *prev;

	struct istream *input;
	const char *path;
	unsigned int linenum;
};

struct parser_context {
	pool_t pool;
	const char *path;

	ARRAY_DEFINE(all_parsers, struct config_filter_parser *);
	struct config_module_parser *root_parsers;
	struct config_section_stack *cur_section;
	struct input_stack *cur_input;

	struct config_filter_context *filter;
};

static const enum settings_parser_flags settings_parser_flags =
	SETTINGS_PARSER_FLAG_IGNORE_UNKNOWN_KEYS |
	SETTINGS_PARSER_FLAG_TRACK_CHANGES;

struct config_module_parser *config_module_parsers;
struct config_filter_context *config_filter;

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

static void config_add_type(struct setting_parser_context *parser,
			    const char *line, const char *section_name)
{
	const struct setting_parser_info *info;
	const char *p;
	string_t *str;
	int ret;

	info = settings_parse_get_prev_info(parser);
	if (info->type_offset == (size_t)-1)
		return;

	str = t_str_new(256);
	p = strchr(line, '=');
	str_append_n(str, line, p-line);
	str_append_c(str, SETTINGS_SEPARATOR);
	str_append(str, p+1);
	str_append_c(str, SETTINGS_SEPARATOR);
	str_append(str, info_type_name_find(info));
	str_append_c(str, '=');
	str_append(str, section_name);

	ret = settings_parse_line(parser, str_c(str));
	i_assert(ret > 0);
}

static int
config_apply_line(struct parser_context *ctx, const char *key,
		  const char *line, const char *section_name,
		  const char **error_r)
{
	struct config_module_parser *l;
	bool found = FALSE;
	int ret;

	for (l = ctx->cur_section->parsers; l->root != NULL; l++) {
		ret = settings_parse_line(l->parser, line);
		if (ret > 0) {
			found = TRUE;
			if (section_name != NULL)
				config_add_type(l->parser, line, section_name);
		} else if (ret < 0) {
			*error_r = settings_parser_get_error(l->parser);
			return -1;
		}
	}
	if (!found) {
		*error_r = t_strconcat("Unknown setting: ", key, NULL);
		return -1;
	}
	*error_r = NULL;
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
config_add_new_parser(struct parser_context *ctx)
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
config_add_new_section(struct parser_context *ctx)
{
	struct config_section_stack *section;

	section = p_new(ctx->pool, struct config_section_stack, 1);
	section->prev = ctx->cur_section;
	section->filter = ctx->cur_section->filter;
	section->parsers = ctx->cur_section->parsers;
	return section;
}

static struct config_filter_parser *
config_filter_parser_find(struct parser_context *ctx,
			  const struct config_filter *filter)
{
	struct config_filter_parser *const *parsers;
	unsigned int i, count;

	parsers = array_get(&ctx->all_parsers, &count);
	for (i = 0; i < count; i++) {
		if (config_filters_equal(&parsers[i]->filter, filter))
			return parsers[i];
	}
	return NULL;
}

static bool
config_filter_add_new_filter(struct parser_context *ctx,
			     const char *key, const char *value,
			     const char **error_r)
{
	struct config_filter *filter = &ctx->cur_section->filter;
	struct config_filter *parent = &ctx->cur_section->prev->filter;
	struct config_filter_parser *parser;

	if (strcmp(key, "protocol") == 0) {
		if (parent->service != NULL)
			*error_r = "protocol must not be under protocol";
		else
			filter->service = p_strdup(ctx->pool, value);
	} else if (strcmp(key, "local_ip") == 0) {
		if (parent->remote_bits > 0)
			*error_r = "local_ip must not be under remote_ip";
		else if (parent->service != NULL)
			*error_r = "local_ip must not be under protocol";
		else if (net_parse_range(value, &filter->local_net,
					 &filter->local_bits) < 0)
			*error_r = "Invalid network mask";
		else if (parent->local_bits > filter->local_bits ||
			 (parent->local_bits > 0 &&
			  !net_is_in_network(&filter->local_net,
					     &parent->local_net,
					     parent->local_bits)))
			*error_r = "local_ip not a subset of parent local_ip";
	} else if (strcmp(key, "remote_ip") == 0) {
		if (parent->service != NULL)
			*error_r = "remote_ip must not be under protocol";
		else if (net_parse_range(value, &filter->remote_net,
					 &filter->remote_bits) < 0)
			*error_r = "Invalid network mask";
		else if (parent->remote_bits > filter->remote_bits ||
			 (parent->remote_bits > 0 &&
			  !net_is_in_network(&filter->remote_net,
					     &parent->remote_net,
					     parent->remote_bits)))
			*error_r = "remote_ip not a subset of parent remote_ip";
	} else {
		return FALSE;
	}

	parser = config_filter_parser_find(ctx, filter);
	if (parser != NULL)
		ctx->cur_section->parsers = parser->parsers;
	else
		config_add_new_parser(ctx);
	return TRUE;
}

static int
config_filter_parser_check(struct parser_context *ctx,
			   const struct config_module_parser *p,
			   const char **error_r)
{
	for (; p->root != NULL; p++) {
		settings_parse_var_skip(p->parser);
		if (!settings_parser_check(p->parser, ctx->pool, error_r))
			return -1;
	}
	return 0;
}

static int
config_all_parsers_check(struct parser_context *ctx,
			 struct config_filter_context *new_filter,
			 const char **error_r)
{
	struct config_filter_parser *const *parsers;
	struct config_module_parser *tmp_parsers;
	unsigned int i, count;
	pool_t tmp_pool;
	int ret = 0;

	tmp_pool = pool_alloconly_create("config parsers check", 1024*32);
	parsers = array_get(&ctx->all_parsers, &count);
	i_assert(count > 0 && parsers[count-1] == NULL);
	count--;
	for (i = 0; i < count && ret == 0; i++) {
		if (config_filter_parsers_get(new_filter, tmp_pool,
					      &parsers[i]->filter,
					      &tmp_parsers, error_r) < 0) {
			ret = -1;
			break;
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

	fd = open(path, O_RDONLY);
	if (fd == -1) {
		*error_r = t_strdup_printf("%s: Can't open file %s: %m",
					   key, path);
		return -1;
	}
	while ((ret = read(fd, buf, sizeof(buf))) > 0)
		str_append_n(str, buf, ret);
	if (ret < 0) {
		*error_r = t_strdup_printf("%s: read(%s) failed: %m",
					   key, path);
	}
	(void)close(fd);
	return ret < 0 ? -1 : 0;
}

static int settings_add_include(struct parser_context *ctx, const char *path,
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

	new_input = t_new(struct input_stack, 1);
	new_input->prev = ctx->cur_input;
	new_input->path = t_strdup(path);
	new_input->input = i_stream_create_fd(fd, (size_t)-1, TRUE);
	i_stream_set_return_partial_line(new_input->input, TRUE);
	ctx->cur_input = new_input;
	return 0;
}

static int
settings_include(struct parser_context *ctx, const char *pattern,
		 bool ignore_errors, const char **error_r)
{
#ifdef HAVE_GLOB
	glob_t globbers;
	unsigned int i;

	switch (glob(pattern, GLOB_BRACE, NULL, &globbers)) {
	case 0:
		break;
	case GLOB_NOSPACE:
		*error_r = "glob() failed: Not enough memory";
		return -1;
	case GLOB_ABORTED:
		*error_r = "glob() failed: Read error";
		return -1;
	case GLOB_NOMATCH:
		if (ignore_errors)
			return 0;
		*error_r = "No matches";
		return -1;
	default:
		*error_r = "glob() failed: Unknown error";
		return -1;
	}

	/* iterate throuth the different files matching the globbing */
	for (i = 0; i < globbers.gl_pathc; i++) {
		if (settings_add_include(ctx, globbers.gl_pathv[i],
					 ignore_errors, error_r) < 0)
			return -1;
	}
	globfree(&globbers);
	return 0;
#else
	return settings_add_include(ctx, pattern, ignore_errors, error_r);
#endif
}

enum config_line_type {
	CONFIG_LINE_TYPE_SKIP,
	CONFIG_LINE_TYPE_ERROR,
	CONFIG_LINE_TYPE_KEYVALUE,
	CONFIG_LINE_TYPE_KEYFILE,
	CONFIG_LINE_TYPE_SECTION_BEGIN,
	CONFIG_LINE_TYPE_SECTION_END,
	CONFIG_LINE_TYPE_INCLUDE,
	CONFIG_LINE_TYPE_INCLUDE_TRY
};

static enum config_line_type
config_parse_line(struct parser_context *ctx, char *line, string_t *full_line,
		  const char **key_r, const char **value_r)
{
	const char *key;
	unsigned int len;
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
	while (IS_WHITE(line[len-1]))
		len--;
	line[len] = '\0';

	if (len > 0 && line[len-1] == '\\') {
		/* continues in next line */
		line[len-1] = '\0';
		str_append(full_line, line);
		return CONFIG_LINE_TYPE_SKIP;
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
			*value_r = line + 1;
			return CONFIG_LINE_TYPE_KEYFILE;
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
		*value_r = line;
		while (!IS_WHITE(*line) && *line != '\0')
			line++;

		if (*line != '\0') {
			*line++ = '\0';
			while (IS_WHITE(*line))
				line++;
		}
		if (*line != '{') {
			*value_r = "Expecting '='";
			return CONFIG_LINE_TYPE_ERROR;
		}
		if (line[1] != '\0') {
			*value_r = "Garbage after '{'";
			return CONFIG_LINE_TYPE_ERROR;
		}
	}
	return CONFIG_LINE_TYPE_SECTION_BEGIN;
}

static int config_parse_finish(struct parser_context *ctx, const char **error_r)
{
	struct config_filter_context *new_filter;
	const char *error;

	new_filter = config_filter_init(ctx->pool);
	(void)array_append_space(&ctx->all_parsers);
	config_filter_add_all(new_filter, array_idx(&ctx->all_parsers, 0));

	if (config_all_parsers_check(ctx, new_filter, &error) < 0) {
		*error_r = t_strdup_printf("Error in configuration file %s: %s",
					   ctx->path, error);
		return -1;
	}

	if (config_filter != NULL)
		config_filter_deinit(&config_filter);
	config_module_parsers = ctx->root_parsers;
	config_filter = new_filter;
	return 0;
}

int config_parse_file(const char *path, bool expand_files,
		      const char **error_r)
{
	struct input_stack root;
	struct parser_context ctx;
	unsigned int pathlen = 0;
	unsigned int i, count, counter = 0;
	const char *errormsg, *key, *value, *section_name;
	string_t *str, *full_line;
	enum config_line_type type;
	char *line;
	int fd, ret = 0;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		*error_r = t_strdup_printf("open(%s) failed: %m", path);
		return 0;
	}

	memset(&ctx, 0, sizeof(ctx));
	ctx.pool = pool_alloconly_create("config file parser", 1024*64);
	ctx.path = path;

	for (count = 0; all_roots[count] != NULL; count++) ;
	ctx.root_parsers =
		p_new(ctx.pool, struct config_module_parser, count+1);
	for (i = 0; i < count; i++) {
		ctx.root_parsers[i].root = all_roots[i];
		ctx.root_parsers[i].parser =
			settings_parser_init(ctx.pool, all_roots[i],
					     settings_parser_flags);
	}

	memset(&root, 0, sizeof(root));
	root.path = path;
	ctx.cur_input = &root;

	p_array_init(&ctx.all_parsers, ctx.pool, 128);
	ctx.cur_section = p_new(ctx.pool, struct config_section_stack, 1);
	config_add_new_parser(&ctx);

	str = t_str_new(256);
	full_line = t_str_new(512);
	errormsg = NULL;
	ctx.cur_input->input = i_stream_create_fd(fd, (size_t)-1, TRUE);
	i_stream_set_return_partial_line(ctx.cur_input->input, TRUE);
prevfile:
	while ((line = i_stream_read_next_line(ctx.cur_input->input)) != NULL) {
		ctx.cur_input->linenum++;
		type = config_parse_line(&ctx, line, full_line,
					 &key, &value);
		switch (type) {
		case CONFIG_LINE_TYPE_SKIP:
			break;
		case CONFIG_LINE_TYPE_ERROR:
			errormsg = value;
			break;
		case CONFIG_LINE_TYPE_KEYVALUE:
		case CONFIG_LINE_TYPE_KEYFILE:
			str_truncate(str, pathlen);
			str_append(str, key);
			str_append_c(str, '=');

			if (type != CONFIG_LINE_TYPE_KEYFILE)
				str_append(str, value);
			else if (!expand_files) {
				str_append_c(str, '<');
				str_append(str, value);
			} else if (str_append_file(str, key, value, &errormsg) < 0) {
				/* file reading failed */
				break;
			}
			(void)config_apply_line(&ctx, key, str_c(str), NULL, &errormsg);
			break;
		case CONFIG_LINE_TYPE_SECTION_BEGIN:
			ctx.cur_section = config_add_new_section(&ctx);
			ctx.cur_section->pathlen = pathlen;

			if (config_filter_add_new_filter(&ctx, key, value,
							 &errormsg)) {
				/* new filter */
				break;
			}

			/* new config section */
			if (*value == '\0') {
				/* no section name, use a counter */
				section_name = dec2str(counter++);
			} else {
				section_name = settings_section_escape(value);
			}
			str_truncate(str, pathlen);
			str_append(str, key);
			pathlen = str_len(str);

			str_append_c(str, '=');
			str_append(str, section_name);

			if (config_apply_line(&ctx, key, str_c(str), value, &errormsg) < 0)
				break;

			str_truncate(str, pathlen);
			str_append_c(str, SETTINGS_SEPARATOR);
			str_append(str, section_name);
			str_append_c(str, SETTINGS_SEPARATOR);
			pathlen = str_len(str);
			break;
		case CONFIG_LINE_TYPE_SECTION_END:
			if (ctx.cur_section->prev == NULL)
				errormsg = "Unexpected '}'";
			else {
				pathlen = ctx.cur_section->pathlen;
				ctx.cur_section = ctx.cur_section->prev;
			}
			break;
		case CONFIG_LINE_TYPE_INCLUDE:
		case CONFIG_LINE_TYPE_INCLUDE_TRY:
			(void)settings_include(&ctx, fix_relative_path(value, ctx.cur_input),
					       type == CONFIG_LINE_TYPE_INCLUDE_TRY,
					       &errormsg);
			break;
		}

		if (errormsg != NULL) {
			*error_r = t_strdup_printf(
				"Error in configuration file %s line %d: %s",
				ctx.cur_input->path, ctx.cur_input->linenum,
				errormsg);
			ret = -1;
			break;
		}
		str_truncate(full_line, 0);
	}

	i_stream_destroy(&ctx.cur_input->input);
	ctx.cur_input = ctx.cur_input->prev;
	if (line == NULL && ctx.cur_input != NULL)
		goto prevfile;

	if (ret == 0)
		ret = config_parse_finish(&ctx, error_r);
	if (ret < 0) {
		pool_unref(&ctx.pool);
		return -1;
	}
	return 1;
}

void config_parse_load_modules(void)
{
	struct module *modules, *m;
	const struct setting_parser_info **roots;
	ARRAY_DEFINE(new_roots, const struct setting_parser_info *);
	unsigned int i;

	modules = module_dir_load(CONFIG_MODULE_DIR, NULL, FALSE, NULL);
	module_dir_init(modules);

	i_array_init(&new_roots, 64);
	for (m = modules; m != NULL; m = m->next) {
		roots = module_get_symbol(m,
			t_strdup_printf("%s_set_roots", m->name));
		if (roots != NULL) {
			for (i = 0; roots[i] != NULL; i++)
				array_append(&new_roots, &roots[i], 1);
		}
	}
	if (array_count(&new_roots) > 0) {
		/* modules added new settings. add the defaults and start
		   using the new list. */
		for (i = 0; all_roots[i] != NULL; i++)
			array_append(&new_roots, &all_roots[i], 1);
		(void)array_append_space(&new_roots);
		all_roots = array_idx(&new_roots, 0);
	}
}
