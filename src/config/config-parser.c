/* Copyright (C) 2005-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "hash.h"
#include "strescape.h"
#include "istream.h"
#include "settings-parser.h"
#include "all-settings.h"
#include "config-parser.h"

#include <unistd.h>
#include <fcntl.h>

#define IS_WHITE(c) ((c) == ' ' || (c) == '\t')

struct input_stack {
	struct input_stack *prev;

	struct istream *input;
	const char *path;
	unsigned int linenum;
};

static const char *
config_parse_line(pool_t pool, const char *key, const char *line,
		  const struct setting_parser_info **info_r)
{
	enum settings_parser_flags parser_flags =
                SETTINGS_PARSER_FLAG_IGNORE_UNKNOWN_KEYS;
	struct config_setting_parser_list *l;
	bool found = FALSE;
	int ret;

	*info_r = NULL;
	for (l = config_setting_parsers; l->module_name != NULL; l++) {
		if (l->parser == NULL) {
			l->parser = settings_parser_init(pool, l->root,
							 parser_flags);
		}

		ret = settings_parse_line(l->parser, line);
		if (ret > 0) {
			found = TRUE;
			*info_r = settings_parse_get_prev_info(l->parser);
		} else if (ret < 0)
			return settings_parser_get_error(l->parser);
	}

	return found ? NULL : t_strconcat("Unknown setting: ", key, NULL);
}

struct settings_export_context {
	pool_t pool;
	ARRAY_TYPE(const_string) *dest;
	string_t *value;
	string_t *prefix;
	struct hash_table *keys;
	bool export_defaults;
};

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

	for (def = info->defines; def->key != NULL; def++) {
		value = CONST_PTR_OFFSET(set, def->offset);
		default_value = info->defaults == NULL ? NULL :
			CONST_PTR_OFFSET(info->defaults, def->offset);

		count = 0;
		str_truncate(ctx->value, 0);
		switch (def->type) {
		case SET_INTERNAL:
			break;
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
			     null_strcmp(sval, dval) != 0) && sval != NULL)
				str_append(ctx->value, sval);
			break;
		}
		case SET_STR: {
			const char *const *val = value;
			const char *const *_dval = default_value;
			const char *dval = _dval == NULL ? NULL : *_dval;

			if ((ctx->export_defaults ||
			     null_strcmp(*val, dval) != 0) && *val != NULL)
				str_append(ctx->value, *val);
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

			str = key;
			array_append(ctx->dest, &str, 1);
			str = "0";
			array_append(ctx->dest, &str, 1);

			strings = array_get(val, &count);
			i_assert(count % 2 == 0);
			for (i = 0; i < count; i += 2) {
				str = p_strdup_printf(ctx->pool, "%s%s%c0%c%s",
						      str_c(ctx->prefix),
						      def->key,
						      SETTINGS_SEPARATOR,
						      SETTINGS_SEPARATOR,
						      strings[i]);
				array_append(ctx->dest, &str, 1);
				str = p_strdup(ctx->pool, strings[i+1]);
				array_append(ctx->dest, &str, 1);
			}
			count = 0;
			break;
		}
		}
		if (str_len(ctx->value) > 0) {
			key = p_strconcat(ctx->pool, str_c(ctx->prefix),
					  def->key, NULL);
			if (hash_table_lookup(ctx->keys, key) == NULL) {
				str = key;
				array_append(ctx->dest, &str, 1);
				str = p_strdup(ctx->pool, str_c(ctx->value));
				array_append(ctx->dest, &str, 1);
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

static void config_export(pool_t pool, ARRAY_TYPE(const_string) *dest)
{
	struct config_setting_parser_list *l;
	struct settings_export_context ctx;
	const void *set;

	memset(&ctx, 0, sizeof(ctx));
	ctx.pool = pool;
	ctx.dest = dest;
	ctx.export_defaults = FALSE;
	ctx.value = t_str_new(256);
	ctx.prefix = t_str_new(64);
	ctx.keys = hash_table_create(default_pool, ctx.pool, 0,
				     str_hash, (hash_cmp_callback_t *)strcmp);

	for (l = config_setting_parsers; l->module_name != NULL; l++) {
		if (l->parser != NULL) {
			set = settings_parser_get(l->parser);
			settings_export(&ctx, l->root, set);
		}
	}
	hash_table_destroy(&ctx.keys);
}

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

void config_parse_file(pool_t dest_pool, ARRAY_TYPE(const_string) *dest,
		       const char *path, const char *service)
{
	struct input_stack root, *input, *new_input;
	ARRAY_DEFINE(pathlen_stack, unsigned int);
	ARRAY_TYPE(const_string) auth_defaults;
	const struct setting_parser_info *info;
	struct config_setting_parser_list *l;
	unsigned int pathlen = 0;
	unsigned int counter = 0, auth_counter = 0, cur_counter;
	const char *errormsg, *name, *type_name;
	char *line, *key, *p;
	int fd, ret, ignore;
	string_t *str, *full_line;
	size_t len;
	pool_t pool;

	pool = pool_alloconly_create("config file parser", 10240);

	fd = open(path, O_RDONLY);
	if (fd < 0)
		i_fatal("open(%s) failed: %m", path);

	t_array_init(&pathlen_stack, 10);
	t_array_init(&auth_defaults, 32);

	errormsg = config_parse_line(pool, "0", "auth=0", &info);
	i_assert(errormsg == NULL);

	memset(&root, 0, sizeof(root));
	root.path = path;
	input = &root;

	str = t_str_new(256);
	full_line = t_str_new(512);
	errormsg = NULL; ignore = 0;
newfile:
	input->input = i_stream_create_fd(fd, (size_t)-1, TRUE);
	i_stream_set_return_partial_line(input->input, TRUE);
prevfile:
	while ((line = i_stream_read_next_line(input->input)) != NULL) {
		input->linenum++;

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

			for (tmp = input; tmp != NULL; tmp = tmp->prev) {
				if (strcmp(tmp->path, line) == 0)
					break;
			}
			if (tmp != NULL) {
				errormsg = "Recursive include";
			} else if ((fd = open(line, O_RDONLY)) != -1) {
				new_input = t_new(struct input_stack, 1);
				new_input->prev = input;
				new_input->path = t_strdup(line);
				input = new_input;
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
			str_append(str, line);
			if (ignore > 0) {
				/* ignore this setting */
			} else if (pathlen == 0 &&
				   strncmp(str_c(str), "auth_", 5) == 0) {
				/* verify that the setting is valid,
				   but delay actually adding it */
				const char *s = t_strdup(str_c(str) + 5);

				str_truncate(str, 0);
				str_printfa(str, "auth/0/%s=%s", key + 5, line);
				errormsg = config_parse_line(pool, key + 5, str_c(str), &info);
				array_append(&auth_defaults, &s, 1);
			} else {
				errormsg = config_parse_line(pool, key, str_c(str), &info);
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
			else if (ignore > 0) {
				ignore++;
			} else if (strcmp(key, "protocol") == 0) {
				array_append(&pathlen_stack, &pathlen, 1);
				ignore = strcmp(name, service) != 0;
			} else {
				array_append(&pathlen_stack, &pathlen, 1);

				str_truncate(str, pathlen);
				str_append(str, key);
				pathlen = str_len(str);

				if (strcmp(key, "auth") == 0)
					cur_counter = auth_counter++;
				else
					cur_counter = counter++;

				str_append_c(str, '=');
				str_printfa(str, "%u", cur_counter);
				if (cur_counter == 0 && strcmp(key, "auth") == 0) {
					/* already added this */
				} else {
					errormsg = config_parse_line(pool, key,
								     str_c(str), &info);
				}

				str_truncate(str, pathlen);
				str_append_c(str, SETTINGS_SEPARATOR);
				str_printfa(str, "%u", cur_counter);
				str_append_c(str, SETTINGS_SEPARATOR);
				pathlen = str_len(str);

				if (errormsg == NULL && info->type_offset != (size_t)-1) {
					type_name = info_type_name_find(info);
					str_append(str, type_name);
					str_append_c(str, '=');
					str_append(str, name);
					errormsg = config_parse_line(pool, type_name,
								     str_c(str), &info);

					str_truncate(str, pathlen);
				}

				if (strcmp(key, "auth") == 0 && errormsg == NULL) {
					/* add auth default settings */
					const char *const *lines;
					unsigned int i, count;

					lines = array_get(&auth_defaults, &count);
					for (i = 0; i < count; i++) {
						str_truncate(str, pathlen);

						p = strchr(lines[i], '=');
						str_append(str, lines[i]);

						errormsg = config_parse_line(pool, t_strdup_until(lines[i], p), str_c(str), &info);
						i_assert(errormsg == NULL);
					}
				}
			}
		} else {
			/* c) */
			unsigned int pathlen_count;
			const unsigned int *arr;

			if (ignore > 0)
				ignore--;

			arr = array_get(&pathlen_stack, &pathlen_count);
			if (pathlen_count == 0)
				errormsg = "Unexpected '}'";
			else {
				pathlen = arr[pathlen_count - 1];
				array_delete(&pathlen_stack,
					     pathlen_count - 1, 1);
			}
		}

		if (errormsg != NULL) {
			i_fatal("Error in configuration file %s line %d: %s",
				input->path, input->linenum, errormsg);
			break;
		}
		str_truncate(full_line, 0);
	}

	i_stream_destroy(&input->input);
	input = input->prev;
	if (line == NULL && input != NULL)
		goto prevfile;

	for (l = config_setting_parsers; l->module_name != NULL; l++) {
		if (l->parser == NULL)
			continue;

		if (!settings_parser_check(l->parser, pool, &errormsg)) {
			i_fatal("Error in configuration file %s: %s",
				path, errormsg);
		}
	}

	config_export(dest_pool, dest);
}
