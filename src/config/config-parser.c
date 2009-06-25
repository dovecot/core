/* Copyright (C) 2005-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "hash.h"
#include "strescape.h"
#include "istream.h"
#include "settings-parser.h"
#include "config-filter.h"
#include "config-parser.h"

#include <unistd.h>
#include <fcntl.h>

#define IS_WHITE(c) ((c) == ' ' || (c) == '\t')

struct config_filter_stack {
	struct config_filter_stack *prev;
	struct config_filter filter;
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

	ARRAY_DEFINE(all_parsers, struct config_filter_parser_list *);
	/* parsers matching cur_filter */
	ARRAY_TYPE(config_setting_parsers) cur_parsers;
	struct config_filter_stack *cur_filter;
	struct input_stack *cur_input;

	struct config_filter_context *filter;
};

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

static const char *
config_parsers_parse_line(struct config_setting_parser_list *parsers,
			  const char *key, const char *line,
			  const char *section_name)
{
	struct config_setting_parser_list *l;
	bool found = FALSE;
	int ret;

	for (l = parsers; l->module_name != NULL; l++) {
		ret = settings_parse_line(l->parser, line);
		if (ret > 0) {
			found = TRUE;
			if (section_name != NULL)
				config_add_type(l->parser, line, section_name);
		} else if (ret < 0)
			return settings_parser_get_error(l->parser);
	}

	return found ? NULL : t_strconcat("Unknown setting: ", key, NULL);
}

static const char *
config_parse_line(struct config_setting_parser_list *const *all_parsers,
		  const char *key, const char *line, const char *section_name)
{
	const char *ret;

	for (; *all_parsers != NULL; all_parsers++) {
		ret = config_parsers_parse_line(*all_parsers, key, line,
						section_name);
		if (ret != NULL)
			return ret;
	}
	return NULL;
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

static struct config_setting_parser_list *
config_setting_parser_list_dup(pool_t pool,
			       const struct config_setting_parser_list *src)
{
	struct config_setting_parser_list *dest;
	unsigned int i, count;

	for (count = 0; src[count].module_name != NULL; count++) ;

	dest = p_new(pool, struct config_setting_parser_list, count + 1);
	for (i = 0; i < count; i++) {
		dest[i] = src[i];
		dest[i].parser = settings_parser_dup(src[i].parser, pool);
	}
	return dest;
}

static struct config_filter_parser_list *
config_add_new_parser(struct parser_context *ctx)
{
	struct config_filter_parser_list *parser;
	struct config_setting_parser_list *const *cur_parsers;
	unsigned int count;

	parser = p_new(ctx->pool, struct config_filter_parser_list, 1);
	parser->filter = ctx->cur_filter->filter;

	cur_parsers = array_get(&ctx->cur_parsers, &count);
	if (count == 0) {
		/* first one */
		parser->parser_list = config_setting_parsers;
	} else {
		/* duplicate the first settings list */
		parser->parser_list =
			config_setting_parser_list_dup(ctx->pool,
						       cur_parsers[0]);
	}

	array_append(&ctx->all_parsers, &parser, 1);
	return parser;
}

static void config_add_new_filter(struct parser_context *ctx)
{
	struct config_filter_stack *filter;

	filter = p_new(ctx->pool, struct config_filter_stack, 1);
	filter->prev = ctx->cur_filter;
	filter->filter = ctx->cur_filter->filter;
	ctx->cur_filter = filter;
}

static struct config_setting_parser_list *const *
config_update_cur_parsers(struct parser_context *ctx)
{
	struct config_filter_parser_list *const *all_parsers;
	unsigned int i, count;
	bool full_found = FALSE;

	array_clear(&ctx->cur_parsers);

	all_parsers = array_get(&ctx->all_parsers, &count);
	for (i = 0; i < count; i++) {
		if (!config_filter_match(&ctx->cur_filter->filter,
					 &all_parsers[i]->filter))
			continue;

		if (config_filters_equal(&all_parsers[i]->filter,
					 &ctx->cur_filter->filter)) {
			array_insert(&ctx->cur_parsers, 0,
				     &all_parsers[i]->parser_list, 1);
			full_found = TRUE;
		} else {
			array_append(&ctx->cur_parsers,
				     &all_parsers[i]->parser_list, 1);
		}
	}
	i_assert(full_found);
	(void)array_append_space(&ctx->cur_parsers);
	return array_idx(&ctx->cur_parsers, 0);
}

static void
config_filter_parser_list_check(struct parser_context *ctx,
				struct config_filter_parser_list *parser)
{
	struct config_setting_parser_list *l = parser->parser_list;
	const char *errormsg;

	for (; l->module_name != NULL; l++) {
		if (!settings_parser_check(l->parser, ctx->pool, &errormsg)) {
			i_fatal("Error in configuration file %s: %s",
				ctx->path, errormsg);
		}
	}
}

static void
config_all_parsers_check(struct parser_context *ctx)
{
	struct config_filter_parser_list *const *parsers;
	unsigned int i, count;

	parsers = array_get(&ctx->all_parsers, &count);
	for (i = 0; i < count; i++)
		config_filter_parser_list_check(ctx, parsers[i]);
}

static void
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
		return;
	}
	while ((ret = read(fd, buf, sizeof(buf))) > 0)
		str_append_n(str, buf, ret);
	if (ret < 0) {
		*error_r = t_strdup_printf("%s: read(%s) failed: %m",
					   key, path);
	}
	(void)close(fd);
}

void config_parse_file(const char *path, bool expand_files)
{
	enum settings_parser_flags parser_flags =
                SETTINGS_PARSER_FLAG_IGNORE_UNKNOWN_KEYS;
	struct input_stack root, *new_input;
	ARRAY_TYPE(const_string) auth_defaults;
	struct config_setting_parser_list *l, *const *parsers;
	struct parser_context ctx;
	unsigned int pathlen = 0;
	unsigned int counter = 0, auth_counter = 0, cur_counter;
	const char *errormsg, *name;
	char *line, *key, *p;
	int fd, ret;
	string_t *str, *full_line;
	size_t len;

	memset(&ctx, 0, sizeof(ctx));
	ctx.pool = pool_alloconly_create("config file parser", 1024*64);
	ctx.path = path;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		i_fatal("open(%s) failed: %m", path);

	t_array_init(&auth_defaults, 32);

	for (l = config_setting_parsers; l->module_name != NULL; l++) {
		i_assert(l->parser == NULL);
		l->parser = settings_parser_init(ctx.pool, l->root, parser_flags);
	}

	t_array_init(&ctx.cur_parsers, 128);
	p_array_init(&ctx.all_parsers, ctx.pool, 128);
	ctx.cur_filter = p_new(ctx.pool, struct config_filter_stack, 1);
	config_add_new_parser(&ctx);
	parsers = config_update_cur_parsers(&ctx);

	errormsg = config_parse_line(parsers, "0", "auth=0", NULL);
	i_assert(errormsg == NULL);
	errormsg = config_parse_line(parsers, "name", "auth/0/name=default", NULL);
	i_assert(errormsg == NULL);

	memset(&root, 0, sizeof(root));
	root.path = path;
	ctx.cur_input = &root;

	str = t_str_new(256);
	full_line = t_str_new(512);
	errormsg = NULL;
newfile:
	ctx.cur_input->input = i_stream_create_fd(fd, (size_t)-1, TRUE);
	i_stream_set_return_partial_line(ctx.cur_input->input, TRUE);
prevfile:
	while ((line = i_stream_read_next_line(ctx.cur_input->input)) != NULL) {
		ctx.cur_input->linenum++;

		/* @UNSAFE: line is modified */

		/* skip whitespace */
		while (IS_WHITE(*line))
			line++;

		/* ignore comments or empty lines */
		if (*line == '#' || *line == '\0')
			continue;

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
			continue;
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

		ret = 1;
		if (strcmp(key, "!include_try") == 0 ||
		    strcmp(key, "!include") == 0) {
			struct input_stack *tmp;
			const char *path;

			path = fix_relative_path(line, ctx.cur_input);
			for (tmp = ctx.cur_input; tmp != NULL; tmp = tmp->prev) {
				if (strcmp(tmp->path, path) == 0)
					break;
			}
			if (tmp != NULL) {
				errormsg = "Recursive include";
			} else if ((fd = open(path, O_RDONLY)) != -1) {
				new_input = t_new(struct input_stack, 1);
				new_input->prev = ctx.cur_input;
				new_input->path = t_strdup(path);
				ctx.cur_input = new_input;
				goto newfile;
			} else {
				/* failed, but ignore failures with include_try. */
				if (strcmp(key, "!include") == 0) {
					errormsg = t_strdup_printf(
						"Couldn't open include file %s: %m", line);
				}
			}
		} else if (*line == '=') {
			/* a) */
			*line++ = '\0';
			while (IS_WHITE(*line)) line++;

			len = strlen(line);
			if (len > 0 &&
			    ((*line == '"' && line[len-1] == '"') ||
			     (*line == '\'' && line[len-1] == '\''))) {
				line[len-1] = '\0';
				line = str_unescape(line+1);
			}

			str_truncate(str, pathlen);
			str_append(str, key);
			str_append_c(str, '=');

			if (*line != '<' || !expand_files)
				str_append(str, line);
			else
				str_append_file(str, key, line+1, &errormsg);

			if (errormsg != NULL) {
				/* file reading failed */
			} else if (pathlen == 0 &&
				   strncmp(str_c(str), "auth_", 5) == 0) {
				/* verify that the setting is valid,
				   but delay actually adding it */
				const char *s = t_strdup(str_c(str) + 5);

				str_truncate(str, 0);
				str_printfa(str, "auth/0/%s=", key + 5);
				if (*line != '<' || !expand_files)
					str_append(str, line);
				else
					str_append_file(str, key, line+1, &errormsg);

				errormsg = config_parse_line(parsers, key + 5, str_c(str), NULL);
				array_append(&auth_defaults, &s, 1);
			} else {
				errormsg = config_parse_line(parsers, key, str_c(str), NULL);
			}
		} else if (strcmp(key, "}") != 0 || *line != '\0') {
			/* b) + errors */
			line[-1] = '\0';

			if (*line == '{')
				name = "";
			else {
				name = line;
				while (!IS_WHITE(*line) && *line != '\0')
					line++;

				if (*line != '\0') {
					*line++ = '\0';
					while (IS_WHITE(*line))
						line++;
				}
			}

			if (*line != '{')
				errormsg = "Expecting '='";

			config_add_new_filter(&ctx);
			ctx.cur_filter->pathlen = pathlen;
			if (strcmp(key, "protocol") == 0) {
				ctx.cur_filter->filter.service =
					p_strdup(ctx.pool, name);
				config_add_new_parser(&ctx);
				parsers = config_update_cur_parsers(&ctx);
			} else if (strcmp(key, "local_ip") == 0) {
				if (net_parse_range(name, &ctx.cur_filter->filter.local_net,
						    &ctx.cur_filter->filter.local_bits) < 0)
					errormsg = "Invalid network mask";
				config_add_new_parser(&ctx);
				parsers = config_update_cur_parsers(&ctx);
			} else if (strcmp(key, "remote_ip") == 0) {
				if (net_parse_range(name, &ctx.cur_filter->filter.remote_net,
						    &ctx.cur_filter->filter.remote_bits) < 0)
					errormsg = "Invalid network mask";
				config_add_new_parser(&ctx);
				parsers = config_update_cur_parsers(&ctx);
			} else {
				str_truncate(str, pathlen);
				str_append(str, key);
				pathlen = str_len(str);

				if (strcmp(key, "auth") == 0) {
					cur_counter = auth_counter++;
					if (cur_counter == 0 && strcmp(name, "default") != 0)
						cur_counter = auth_counter++;
				} else {
					cur_counter = counter++;
				}

				str_append_c(str, '=');
				str_printfa(str, "%u", cur_counter);

				if (cur_counter == 0 && strcmp(key, "auth") == 0) {
					/* already added this */
				} else {
					errormsg = config_parse_line(parsers, key, str_c(str), name);
				}

				str_truncate(str, pathlen);
				str_append_c(str, SETTINGS_SEPARATOR);
				str_printfa(str, "%u", cur_counter);
				str_append_c(str, SETTINGS_SEPARATOR);
				pathlen = str_len(str);

				if (strcmp(key, "auth") == 0 && errormsg == NULL) {
					/* add auth default settings */
					const char *const *lines;
					unsigned int i, count;

					lines = array_get(&auth_defaults, &count);
					for (i = 0; i < count; i++) {
						str_truncate(str, pathlen);

						p = strchr(lines[i], '=');
						str_append(str, lines[i]);

						errormsg = config_parse_line(parsers, t_strdup_until(lines[i], p), str_c(str), NULL);
						i_assert(errormsg == NULL);
					}
				}
			}
		} else {
			/* c) */
			if (ctx.cur_filter->prev == NULL)
				errormsg = "Unexpected '}'";
			else {
				pathlen = ctx.cur_filter->pathlen;
				ctx.cur_filter = ctx.cur_filter->prev;
				parsers = config_update_cur_parsers(&ctx);
			}
		}

		if (errormsg != NULL) {
			i_fatal("Error in configuration file %s line %d: %s",
				ctx.cur_input->path, ctx.cur_input->linenum,
				errormsg);
			break;
		}
		str_truncate(full_line, 0);
	}

	i_stream_destroy(&ctx.cur_input->input);
	ctx.cur_input = ctx.cur_input->prev;
	if (line == NULL && ctx.cur_input != NULL)
		goto prevfile;

	config_all_parsers_check(&ctx);

	(void)array_append_space(&ctx.all_parsers);
	config_filter = config_filter_init(ctx.pool);
	config_filter_add_all(config_filter, array_idx(&ctx.all_parsers, 0));
}
