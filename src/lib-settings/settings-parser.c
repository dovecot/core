/* Copyright (c) 2002-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "hash.h"
#include "network.h"
#include "istream.h"
#include "str.h"
#include "strescape.h"
#include "var-expand.h"
#include "settings-parser.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>

#define IS_WHITE(c) ((c) == ' ' || (c) == '\t')

struct setting_link {
        struct setting_link *parent;
	const struct setting_parser_info *info;

	/* Points to array inside parent->set_struct.
	   SET_DEFLIST : array of set_structs
	   SET_STRLIST : array of const_strings */
	ARRAY_TYPE(void_array) *array;
	/* Pointer to structure containing the values */
	void *set_struct;
	/* Pointer to structure containing non-zero values for settings that
	   have been changed. */
	void *change_struct;
	/* SET_DEFLIST: array of change_structs */
	ARRAY_TYPE(void_array) *change_array;
};

struct setting_parser_context {
	pool_t set_pool, parser_pool;
        enum settings_parser_flags flags;
	bool str_vars_are_expanded;

	struct setting_link *roots;
	unsigned int root_count;
	struct hash_table *links;

	unsigned int linenum;
	const char *error;
	const struct setting_parser_info *prev_info;
};

static const struct setting_parser_info strlist_info = {
	MEMBER(module_name) NULL,
	MEMBER(defines) NULL,
	MEMBER(defaults) NULL,

	MEMBER(type_offset) (size_t)-1,
	MEMBER(struct_size) 0,

	MEMBER(parent_offset) (size_t)-1
};

struct setting_parser_context *
settings_parser_init(pool_t set_pool, const struct setting_parser_info *root,
		     enum settings_parser_flags flags)
{
        return settings_parser_init_list(set_pool, &root, 1, flags);
}

static void
setting_parser_copy_defaults(const struct setting_parser_info *info,
			     pool_t pool, void *dest)
{
	const struct setting_define *def;
	const char *p, **strp;

	if (info->defaults == NULL)
		return;

	memcpy(dest, info->defaults, info->struct_size);
	for (def = info->defines; def->key != NULL; def++) {
		switch (def->type) {
		case SET_ENUM: {
			/* fix enums by dropping everything after the
			   first ':' */
			strp = STRUCT_MEMBER_P(dest, def->offset);
			p = strchr(*strp, ':');
			if (p != NULL)
				*strp = p_strdup_until(pool, *strp, p);
			break;
		}
		case SET_STR_VARS: {
			/* insert the unexpanded-character */
			strp = STRUCT_MEMBER_P(dest, def->offset);
			if (*strp != NULL) {
				*strp = p_strconcat(pool,
						    SETTING_STRVAR_UNEXPANDED,
						    *strp, NULL);
			}
			break;
		}
		default:
			break;
		}
	}
}

struct setting_parser_context *
settings_parser_init_list(pool_t set_pool,
			  const struct setting_parser_info *const *roots,
			  unsigned int count, enum settings_parser_flags flags)
{
	struct setting_parser_context *ctx;
	unsigned int i;
	pool_t parser_pool;

	i_assert(count > 0);

	parser_pool = pool_alloconly_create("settings parser", 16384);
	ctx = p_new(parser_pool, struct setting_parser_context, 1);
	ctx->set_pool = set_pool;
	ctx->parser_pool = parser_pool;
	ctx->flags = flags;

	ctx->root_count = count;
	ctx->roots = p_new(ctx->parser_pool, struct setting_link, count);
	for (i = 0; i < count; i++) {
		ctx->roots[i].info = roots[i];
		ctx->roots[i].set_struct =
			p_malloc(ctx->set_pool, roots[i]->struct_size);
		if ((flags & SETTINGS_PARSER_FLAG_TRACK_CHANGES) != 0) {
			ctx->roots[i].change_struct =
				p_malloc(ctx->set_pool, roots[i]->struct_size);
		}
		setting_parser_copy_defaults(roots[i], ctx->set_pool,
					     ctx->roots[i].set_struct);
	}

	ctx->links = hash_table_create(default_pool, ctx->parser_pool, 0,
				       str_hash, (hash_cmp_callback_t *)strcmp);
	pool_ref(ctx->set_pool);
	return ctx;
}

void settings_parser_deinit(struct setting_parser_context **_ctx)
{
	struct setting_parser_context *ctx = *_ctx;

	*_ctx = NULL;
	hash_table_destroy(&ctx->links);
	pool_unref(&ctx->set_pool);
	pool_unref(&ctx->parser_pool);
}

void *settings_parser_get(struct setting_parser_context *ctx)
{
	i_assert(ctx->root_count == 1);

	return ctx->roots[0].set_struct;
}

void **settings_parser_get_list(struct setting_parser_context *ctx)
{
	unsigned int i;
	void **sets;

	sets = t_new(void *, ctx->root_count + 1);
	for (i = 0; i < ctx->root_count; i++)
		sets[i] = ctx->roots[i].set_struct;
	return sets;
}

void *settings_parser_get_changes(struct setting_parser_context *ctx)
{
	i_assert(ctx->root_count == 1);

	return ctx->roots[0].change_struct;
}

const char *settings_parser_get_error(struct setting_parser_context *ctx)
{
	return ctx->error;
}

static const struct setting_define *
setting_define_find(const struct setting_parser_info *info, const char *key)
{
	const struct setting_define *list;

	for (list = info->defines; list->key != NULL; list++) {
		if (strcmp(list->key, key) == 0)
			return list;
	}
	return NULL;
}

static int
get_bool(struct setting_parser_context *ctx, const char *value, bool *result_r)
{
	/* FIXME: eventually we'd want to support only yes/no */
	if (strcasecmp(value, "yes") == 0 ||
	    strcasecmp(value, "y") == 0 || strcmp(value, "1") == 0)
		*result_r = TRUE;
	else if (strcasecmp(value, "no") == 0)
		*result_r = FALSE;
	else {
		ctx->error = p_strconcat(ctx->parser_pool, "Invalid boolean: ",
					 value, NULL);
		return -1;
	}

	return 0;
}

static int
get_uint(struct setting_parser_context *ctx, const char *value,
	 unsigned int *result_r)
{
	int num;

	/* use %i so we can handle eg. 0600 as octal value with umasks */
	if (!sscanf(value, "%i", &num) || num < 0) {
		ctx->error = p_strconcat(ctx->parser_pool, "Invalid number: ",
					 value, NULL);
		return -1;
	}
	*result_r = num;
	return 0;
}

static int get_enum(struct setting_parser_context *ctx, const char *value,
		    char **result_r, const char *allowed_values)
{
	const char *p;

	while (allowed_values != NULL) {
		p = strchr(allowed_values, ':');
		if (p == NULL) {
			if (strcmp(allowed_values, value) == 0)
				break;

			ctx->error = p_strconcat(ctx->parser_pool,
						 "Invalid value: ",
						 value, NULL);
			return -1;
		}

		if (strncmp(allowed_values, value, p - allowed_values) == 0 &&
		    value[p - allowed_values] == '\0')
			break;

		allowed_values = p + 1;
	}

	*result_r = p_strdup(ctx->set_pool, value);
	return 0;
}

static int
get_deflist(struct setting_parser_context *ctx, struct setting_link *parent,
	    const struct setting_parser_info *info,
	    const char *key, const char *value, ARRAY_TYPE(void_array) *result,
	    ARRAY_TYPE(void_array) *change_result)
{
	struct setting_link *link;
	const char *const *list;
	char *full_key;

	i_assert(info->defines != NULL || info == &strlist_info);

	if (!array_is_created(result))
		p_array_init(result, ctx->set_pool, 5);
	if (change_result != NULL && !array_is_created(change_result))
		p_array_init(change_result, ctx->set_pool, 5);

	list = t_strsplit(value, "\t ");
	for (; *list != NULL; list++) {
		if (**list == '\0')
			continue;

		full_key = p_strconcat(ctx->parser_pool, key,
				       SETTINGS_SEPARATOR_S, *list, NULL);
		if (hash_table_lookup(ctx->links, full_key) != NULL) {
			ctx->error = p_strconcat(ctx->parser_pool, full_key,
						 " already exists", NULL);
			return -1;
		}

		link = p_new(ctx->parser_pool, struct setting_link, 1);
		link->parent = parent;
		link->info = info;
		link->array = result;
		link->change_array = change_result;
		hash_table_insert(ctx->links, full_key, link);
	}
	return 0;
}

static int
settings_parse(struct setting_parser_context *ctx, struct setting_link *link,
	       const struct setting_define *def,
	       const char *key, const char *value)
{
        void *ptr, *ptr2, *change_ptr;

	ctx->prev_info = link->info;

	if (link->set_struct == NULL) {
		link->set_struct =
			p_malloc(ctx->set_pool, link->info->struct_size);
		setting_parser_copy_defaults(link->info, ctx->set_pool,
					     link->set_struct);
		array_append(link->array, &link->set_struct, 1);

		if ((ctx->flags & SETTINGS_PARSER_FLAG_TRACK_CHANGES) != 0) {
			link->change_struct = p_malloc(ctx->set_pool,
						       link->info->struct_size);
			array_append(link->change_array,
				     &link->change_struct, 1);
		}

		if (link->info->parent_offset != (size_t)-1 &&
		    link->parent != NULL) {
			ptr = STRUCT_MEMBER_P(link->set_struct,
					      link->info->parent_offset);
			*((void **)ptr) = link->parent->set_struct;
		}
	}

	change_ptr = link->change_struct == NULL ? NULL :
		STRUCT_MEMBER_P(link->change_struct, def->offset);

	ptr = STRUCT_MEMBER_P(link->set_struct, def->offset);
	switch (def->type) {
	case SET_BOOL:
		if (get_bool(ctx, value, (bool *)ptr) < 0)
			return -1;
		break;
	case SET_UINT:
		if (get_uint(ctx, value, (unsigned int *)ptr) < 0)
			return -1;
		break;
	case SET_STR:
		*((char **)ptr) = p_strdup(ctx->set_pool, value);
		break;
	case SET_STR_VARS:
		*((char **)ptr) = p_strconcat(ctx->set_pool,
					      ctx->str_vars_are_expanded ?
					      SETTING_STRVAR_EXPANDED :
					      SETTING_STRVAR_UNEXPANDED,
					      value, NULL);
		break;
	case SET_ENUM:
		/* get the available values from default string */
		i_assert(link->info->defaults != NULL);
		ptr2 = STRUCT_MEMBER_P(link->info->defaults, def->offset);
		if (get_enum(ctx, value, (char **)ptr,
			     *(const char **)ptr2) < 0)
			return -1;
		break;
	case SET_DEFLIST:
		ctx->prev_info = def->list_info;
		return get_deflist(ctx, link, def->list_info,
				   key, value, (ARRAY_TYPE(void_array) *)ptr,
				   (ARRAY_TYPE(void_array) *)change_ptr);
	case SET_STRLIST: {
		ctx->prev_info = &strlist_info;
		if (get_deflist(ctx, link, &strlist_info, key, value,
				(ARRAY_TYPE(void_array) *)ptr, NULL) < 0)
			return -1;
		break;
	}
	}

	if (change_ptr != NULL)
		*((char *)change_ptr) = 1;
	return 0;
}

static bool
settings_find_key(struct setting_parser_context *ctx, const char *key,
		  const struct setting_define **def_r,
		  struct setting_link **link_r)
{
	const struct setting_define *def;
	struct setting_link *link;
	const char *end;
	unsigned int i;

	/* try to find from roots */
	for (i = 0; i < ctx->root_count; i++) {
		def = setting_define_find(ctx->roots[i].info, key);
		if (def != NULL) {
			*def_r = def;
			*link_r = &ctx->roots[i];
			return TRUE;
		}
	}

	/* try to find from links */
	end = strrchr(key, SETTINGS_SEPARATOR);
	if (end == NULL)
		return FALSE;

	link = hash_table_lookup(ctx->links, t_strdup_until(key, end));
	if (link == NULL)
		return FALSE;

	*link_r = link;
	if (link->info == &strlist_info) {
		*def_r = NULL;
		return TRUE;
	} else {
		*def_r = setting_define_find(link->info, end + 1);
		return *def_r != NULL;
	}
}

static int settings_parse_keyvalue(struct setting_parser_context *ctx,
				   const char *key, const char *value)
{
	const struct setting_define *def;
	struct setting_link *link;

	if (settings_find_key(ctx, key, &def, &link)) {
		if (link->info == &strlist_info) {
			void *vkey, *vvalue;

			vkey = p_strdup(ctx->set_pool,
					strrchr(key, SETTINGS_SEPARATOR) + 1);
			vvalue = p_strdup(ctx->set_pool, value);
			array_append(link->array, &vkey, 1);
			array_append(link->array, &vvalue, 1);
			return 1;
		}

		if (settings_parse(ctx, link, def, key, value) < 0)
			return -1;
		return 1;
	} else {
		ctx->error = p_strconcat(ctx->parser_pool,
					 "Unknown setting: ", key, NULL);
		return 0;
	}
}

bool settings_parse_is_valid_key(struct setting_parser_context *ctx,
				 const char *key)
{
	const struct setting_define *def;
	struct setting_link *link;

	return settings_find_key(ctx, key, &def, &link);
}

int settings_parse_line(struct setting_parser_context *ctx, const char *line)
{
	const char *key, *value;
	int ret;

	ctx->error = NULL;
	ctx->prev_info = NULL;

	key = line;
	value = strchr(line, '=');
	if (value == NULL) {
		ctx->error = "Missing '='";
		return -1;
	}

	if (key == value) {
		ctx->error = "Missing key name ('=' at the beginning of line)";
		return -1;
	}

	T_BEGIN {
		key = t_strdup_until(key, value);
		ret = settings_parse_keyvalue(ctx, key, value + 1);
	} T_END;
	return ret;
}

const struct setting_parser_info *
settings_parse_get_prev_info(struct setting_parser_context *ctx)
{
	return ctx->prev_info;
}

static const char *settings_translate_lf(const char *value)
{
	char *dest, *p;

	if (strchr(value, SETTING_STREAM_LF_CHAR[0]) == NULL)
		return value;

	dest = t_strdup_noconst(value);
	for (p = dest; *p != '\0'; p++) {
		if (*p == SETTING_STREAM_LF_CHAR[0])
			*p = '\n';
	}
	return dest;
}

int settings_parse_stream(struct setting_parser_context *ctx,
			  struct istream *input)
{
	bool ignore_unknown_keys =
		(ctx->flags & SETTINGS_PARSER_FLAG_IGNORE_UNKNOWN_KEYS) != 0;
	const char *line;
	int ret;

	while ((line = i_stream_next_line(input)) != NULL) {
		if (*line == '\0') {
			/* empty line finishes it */
			return 0;
		}
		ctx->linenum++;
		if (ctx->linenum == 1 && strncmp(line, "ERROR ", 6) == 0) {
			ctx->error = p_strdup(ctx->parser_pool, line + 6);
			return -1;
		}

		T_BEGIN {
			line = settings_translate_lf(line);
			ret = settings_parse_line(ctx, line);
		} T_END;

		if (ret < 0 || (ret == 0 && !ignore_unknown_keys)) {
			ctx->error = p_strdup_printf(ctx->parser_pool,
				"Line %u: %s", ctx->linenum, ctx->error);
			return -1;
		}
	}
	return 1;
}

int settings_parse_stream_read(struct setting_parser_context *ctx,
			       struct istream *input)
{
	int ret;

	while ((ret = i_stream_read(input)) > 0) {
		if ((ret = settings_parse_stream(ctx, input)) < 0)
			return -1;
		if (ret == 0) {
			/* empty line read */
			return 0;
		}
	}

	switch (ret) {
	case -1:
		if (input->stream_errno != 0) {
			ctx->error = p_strdup_printf(ctx->parser_pool,
						     "read() failed: %m");
		} else {
			ctx->error = "input is missing end-of-settings line";
		}
		break;
	case -2:
		ctx->error = p_strdup_printf(ctx->parser_pool,
					     "Line %u: line too long",
					     ctx->linenum);
		break;
	case 0:
		/* blocks */
		return 1;
	default:
		i_unreached();
	}
	return -1;
}

int settings_parse_file(struct setting_parser_context *ctx,
			const char *path, size_t max_line_length)
{
	struct istream *input;
	int fd, ret;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		ctx->error = p_strdup_printf(ctx->parser_pool,
					     "open(%s) failed: %m", path);
		return -1;
	}

	input = i_stream_create_fd(fd, max_line_length, TRUE);
	ret = settings_parse_stream_read(ctx, input);
	i_stream_unref(&input);

	return ret;
}

static int environ_cmp(char *const *s1, char *const *s2)
{
	return -strcmp(*s1, *s2);
}

int settings_parse_environ(struct setting_parser_context *ctx)
{
	extern char **environ;
	ARRAY_TYPE(string) sorted_envs_arr;
	const char *key, *value;
	char *const *sorted_envs;
	unsigned int i, count;
	int ret = 0;

	if (environ == NULL)
		return 0;

	/* sort the settings first. this is necessary for putenv()
	   implementations (e.g. valgrind) which change the order of strings
	   in environ[] */
	i_array_init(&sorted_envs_arr, 128);
	for (i = 0; environ[i] != NULL; i++)
		array_append(&sorted_envs_arr, &environ[i], 1);
	array_sort(&sorted_envs_arr, environ_cmp);
	sorted_envs = array_get(&sorted_envs_arr, &count);

	for (i = 0; i < count && ret == 0; i++) {
		value = strchr(sorted_envs[i], '=');
		if (value != NULL) T_BEGIN {
			key = t_strdup_until(sorted_envs[i], value++);
			key = t_str_lcase(key);
			if (settings_parse_keyvalue(ctx, key, value) < 0) {
				ctx->error = p_strdup_printf(ctx->parser_pool,
					"Invalid setting %s: %s",
					key, ctx->error);
				ret = -1;
			}
		} T_END;
	}
	array_free(&sorted_envs_arr);
	return ret;
}

int settings_parse_exec(struct setting_parser_context *ctx,
			const char *bin_path, const char *config_path,
			const char *service)
{
	struct istream *input;
	pid_t pid;
	int ret, fd[2], status;

	if (pipe(fd) < 0) {
		i_error("pipe() failed: %m");
		return -1;
	}

	pid = fork();
	if (pid == (pid_t)-1) {
		i_error("fork() failed: %m");
		(void)close(fd[0]);
		(void)close(fd[1]);
		return -1;
	}
	if (pid == 0) {
		/* child */
		static const char *argv[] = {
			NULL,
			"-c", NULL,
			"-p", NULL,
			NULL
		};
		argv[0] = bin_path;
		argv[2] = config_path;
		argv[4] = service;
		(void)close(fd[0]);
		if (dup2(fd[1], STDOUT_FILENO) < 0)
			i_fatal("dup2() failed: %m");

		execv(argv[0], (void *)argv);
		i_fatal_status(FATAL_EXEC, "execv(%s) failed: %m", bin_path);
		return -1;
	}
	(void)close(fd[1]);

	input = i_stream_create_fd(fd[0], (size_t)-1, TRUE);
	ret = settings_parse_stream_read(ctx, input);
	i_stream_destroy(&input);

	if (waitpid(pid, &status, 0) < 0) {
		i_error("waitpid() failed: %m");
		ret = -1;
	} else if (status != 0) {
		i_error("%s returned failure: %d", bin_path, status);
		ret = -1;
	}
	return ret;
}

static bool
settings_parser_check_info(const struct setting_parser_info *info, pool_t pool,
			   void *set, const char **error_r)
{
	const struct setting_define *def;
	const ARRAY_TYPE(void_array) *val;
	void *const *children;
	unsigned int i, count;

	if (info->check_func != NULL) {
		if (!info->check_func(set, pool, error_r))
			return FALSE;
	}

	for (def = info->defines; def->key != NULL; def++) {
		if (def->type != SET_DEFLIST)
			continue;

		val = CONST_PTR_OFFSET(set, def->offset);;
		if (!array_is_created(val))
			continue;

		children = array_get(val, &count);
		for (i = 0; i < count; i++) {
			if (!settings_parser_check_info(def->list_info, pool,
							children[i], error_r))
				return FALSE;
		}
	}
	return TRUE;
}

bool settings_parser_check(struct setting_parser_context *ctx, pool_t pool,
			   const char **error_r)
{
	unsigned int i;

	for (i = 0; i < ctx->root_count; i++) {
		if (!settings_parser_check_info(ctx->roots[i].info, pool,
						ctx->roots[i].set_struct,
						error_r))
		    return FALSE;
	}
	return TRUE;
}

void settings_parse_set_expanded(struct setting_parser_context *ctx,
				 bool is_expanded)
{
	ctx->str_vars_are_expanded = is_expanded;
}

void settings_parse_set_key_expandeded(struct setting_parser_context *ctx,
				       pool_t pool, const char *key)
{
	const struct setting_define *def;
	struct setting_link *link;
	const char **val;

	if (!settings_find_key(ctx, key, &def, &link))
		return;

	val = PTR_OFFSET(link->set_struct, def->offset);
	if (def->type == SET_STR_VARS && *val != NULL) {
		i_assert(**val == SETTING_STRVAR_UNEXPANDED[0] ||
			 **val == SETTING_STRVAR_EXPANDED[0]);
		*val = p_strconcat(pool, SETTING_STRVAR_EXPANDED,
				   *val + 1, NULL);
	}
}

void settings_parse_set_keys_expandeded(struct setting_parser_context *ctx,
					pool_t pool, const char *const *keys)
{
	for (; *keys != NULL; keys++)
		settings_parse_set_key_expandeded(ctx, pool, *keys);
}

void settings_parse_var_skip(struct setting_parser_context *ctx)
{
	unsigned int i;

	for (i = 0; i < ctx->root_count; i++) {
		settings_var_expand(ctx->roots[i].info,
				    ctx->roots[i].set_struct, NULL, NULL);
	}
}

static void
settings_var_expand_info(const struct setting_parser_info *info,
			 pool_t pool, void *set,
			 const struct var_expand_table *table, string_t *str)
{
	const struct setting_define *def;
	void *value, *const *children;
	unsigned int i, count;

	for (def = info->defines; def->key != NULL; def++) {
		value = PTR_OFFSET(set, def->offset);
		switch (def->type) {
		case SET_STR_VARS: {
			const char **val = value;

			if (*val == NULL)
				break;

			if (table == NULL) {
				i_assert(**val == SETTING_STRVAR_EXPANDED[0] ||
					 **val == SETTING_STRVAR_UNEXPANDED[0]);
				*val += 1;
			} else if (**val == SETTING_STRVAR_UNEXPANDED[0]) {
				str_truncate(str, 0);
				var_expand(str, *val + 1, table);
				*val = p_strdup(pool, str_c(str));
			} else {
				i_assert(**val == SETTING_STRVAR_EXPANDED[0]);
				*val += 1;
			}
			break;
		}
		case SET_DEFLIST: {
			const ARRAY_TYPE(void_array) *val = value;

			if (!array_is_created(val))
				break;

			children = array_get(val, &count);
			for (i = 0; i < count; i++) {
				settings_var_expand_info(def->list_info,
							 pool, children[i],
							 table, str);
			}
			break;
		}
		default:
			break;
		}
	}
}

void settings_var_expand(const struct setting_parser_info *info,
			 void *set, pool_t pool,
			 const struct var_expand_table *table)
{
	string_t *str;

	T_BEGIN {
		str = t_str_new(256);
		settings_var_expand_info(info, pool, set, table, str);
	} T_END;
}

bool settings_vars_have_key(const struct setting_parser_info *info, void *set,
			    char var_key, const char *long_var_key,
			    const char **key_r, const char **value_r)
{
	const struct setting_define *def;
	const void *value;
	void *const *children;
	unsigned int i, count;

	for (def = info->defines; def->key != NULL; def++) {
		value = CONST_PTR_OFFSET(set, def->offset);
		switch (def->type) {
		case SET_STR_VARS: {
			const char *const *val = value;

			if (*val == NULL)
				break;

			if (**val == SETTING_STRVAR_UNEXPANDED[0]) {
				if (var_has_key(*val + 1, var_key,
						long_var_key)) {
					*key_r = def->key;
					*value_r = *val + 1;
					return TRUE;
				}
			} else {
				i_assert(**val == SETTING_STRVAR_EXPANDED[0]);
			}
			break;
		}
		case SET_DEFLIST: {
			const ARRAY_TYPE(void_array) *val = value;

			if (!array_is_created(val))
				break;

			children = array_get(val, &count);
			for (i = 0; i < count; i++) {
				if (settings_vars_have_key(def->list_info,
							   children[i], var_key,
							   long_var_key,
							   key_r, value_r))
					return TRUE;
			}
			break;
		}
		default:
			break;
		}
	}
	return FALSE;
}

static void settings_set_parent(const struct setting_parser_info *info,
				void *child, void *parent)
{
	void **ptr;

	if (info->parent_offset == (size_t)-1)
		return;

	ptr = PTR_OFFSET(child, info->parent_offset);
	*ptr = parent;
}

static bool
setting_copy(enum setting_type type, const void *src, void *dest, pool_t pool)
{
	switch (type) {
	case SET_BOOL: {
		const bool *src_bool = src;
		bool *dest_bool = dest;

		*dest_bool = *src_bool;
		break;
	}
	case SET_UINT: {
		const unsigned int *src_uint = src;
		unsigned int *dest_uint = dest;

		*dest_uint = *src_uint;
		break;
	}
	case SET_STR_VARS:
	case SET_STR:
	case SET_ENUM: {
		const char *const *src_str = src;
		const char **dest_str = dest;

		*dest_str = p_strdup(pool, *src_str);
		break;
	}
	case SET_DEFLIST:
		return FALSE;
	case SET_STRLIST: {
		const ARRAY_TYPE(const_string) *src_arr = src;
		ARRAY_TYPE(const_string) *dest_arr = dest;
		const char *const *strings, *dup;
		unsigned int i, count;

		if (!array_is_created(src_arr))
			break;

		strings = array_get(src_arr, &count);
		if (!array_is_created(dest_arr))
			p_array_init(dest_arr, pool, count);
		for (i = 0; i < count; i++) {
			dup = p_strdup(pool, strings[i]);
			array_append(dest_arr, &dup, 1);
		}
		break;
	}
	}
	return TRUE;
}

void *settings_dup(const struct setting_parser_info *info,
		   const void *set, pool_t pool)
{
	const struct setting_define *def;
	const void *src;
	void *dest_set, *dest, *const *children;
	unsigned int i, count;

	/* don't just copy everything from set to dest_set. it may contain
	   some non-setting fields allocated from the original pool. */
	dest_set = p_malloc(pool, info->struct_size);
	for (def = info->defines; def->key != NULL; def++) {
		src = CONST_PTR_OFFSET(set, def->offset);
		dest = PTR_OFFSET(dest_set, def->offset);

		if (!setting_copy(def->type, src, dest, pool)) {
			const ARRAY_TYPE(void_array) *src_arr = src;
			ARRAY_TYPE(void_array) *dest_arr = dest;
			void *child_set;

			if (!array_is_created(src_arr))
				continue;

			children = array_get(src_arr, &count);
			p_array_init(dest_arr, pool, count);
			for (i = 0; i < count; i++) {
				child_set = settings_dup(def->list_info,
							 children[i], pool);
				array_append(dest_arr, &child_set, 1);
				settings_set_parent(def->list_info, child_set,
						    dest_set);
			}
		}
	}
	return dest_set;
}

static void *
settings_changes_dup(const struct setting_parser_info *info,
		     const void *change_set, pool_t pool)
{
	const struct setting_define *def;
	const void *src;
	void *dest_set, *dest, *const *children;
	unsigned int i, count;

	if (change_set == NULL)
		return NULL;

	dest_set = p_malloc(pool, info->struct_size);
	for (def = info->defines; def->key != NULL; def++) {
		src = CONST_PTR_OFFSET(change_set, def->offset);
		dest = PTR_OFFSET(dest_set, def->offset);

		switch (def->type) {
		case SET_BOOL:
		case SET_UINT:
		case SET_STR_VARS:
		case SET_STR:
		case SET_ENUM:
		case SET_STRLIST:
			*((char *)dest) = *((char *)src);
			break;
		case SET_DEFLIST: {
			const ARRAY_TYPE(void_array) *src_arr = src;
			ARRAY_TYPE(void_array) *dest_arr = dest;
			void *child_set;

			if (!array_is_created(src_arr))
				break;

			children = array_get(src_arr, &count);
			p_array_init(dest_arr, pool, count);
			for (i = 0; i < count; i++) {
				child_set = settings_changes_dup(def->list_info,
								 children[i],
								 pool);
				array_append(dest_arr, &child_set, 1);
			}
			break;
		}
		}
	}
	return dest_set;
}

static void
info_update_real(pool_t pool, const struct dynamic_settings_parser *parsers)
{
	/* @UNSAFE */
	struct setting_parser_info *parent;
	ARRAY_DEFINE(defines, struct setting_define);
	ARRAY_TYPE(dynamic_settings_parser) dynamic_parsers;
	struct dynamic_settings_parser new_parser;
	const struct setting_define *cur_defines;
	struct setting_define *new_defines, new_define;
	void *parent_defaults;
	unsigned int i, j;
	size_t offset, new_struct_size;

	parent = parsers[0].info->parent;

	t_array_init(&defines, 128);
	/* add existing defines */
	for (j = 0; parent->defines[j].key != NULL; j++)
		array_append(&defines, &parent->defines[j], 1);
	new_struct_size = parent->struct_size;

	/* add new dynamic defines */
	for (i = 0; parsers[i].name != NULL; i++) {
		i_assert(parsers[i].info->parent == parent);
		cur_defines = parsers[i].info->defines;
		for (j = 0; cur_defines[j].key != NULL; j++) {
			new_define = cur_defines[j];
			new_define.offset += new_struct_size;
			array_append(&defines, &new_define, 1);
		}
		new_struct_size += MEM_ALIGN(parsers[i].info->struct_size);
	}
	new_defines = p_new(pool, struct setting_define,
			    array_count(&defines) + 1);
	memcpy(new_defines, array_idx(&defines, 0),
	       sizeof(*parent->defines) * array_count(&defines));
	parent->defines = new_defines;

	/* update defaults */
	parent_defaults = p_malloc(pool, new_struct_size);
	memcpy(parent_defaults, parent->defaults, parent->struct_size);
	offset = parent->struct_size;
	for (i = 0; parsers[i].name != NULL; i++) {
		memcpy(PTR_OFFSET(parent_defaults, offset),
		       parsers[i].info->defaults, parsers[i].info->struct_size);
		offset += MEM_ALIGN(parsers[i].info->struct_size);
	}
	parent->defaults = parent_defaults;

	/* update dynamic parsers list */
	t_array_init(&dynamic_parsers, 32);
	if (parent->dynamic_parsers != NULL) {
		for (i = 0; parent->dynamic_parsers[i].name != NULL; i++) {
			array_append(&dynamic_parsers,
				     &parent->dynamic_parsers[i], 1);
		}
	}
	offset = parent->struct_size;
	for (i = 0; parsers[i].name != NULL; i++) {
		new_parser = parsers[i];
		new_parser.name = p_strdup(pool, new_parser.name);
		new_parser.struct_offset = offset;
		array_append(&dynamic_parsers, &new_parser, 1);
		offset += MEM_ALIGN(parsers[i].info->struct_size);
	}
	parent->dynamic_parsers =
		p_new(pool, struct dynamic_settings_parser,
		      array_count(&dynamic_parsers) + 1);
	memcpy(parent->dynamic_parsers, array_idx(&dynamic_parsers, 0),
	       sizeof(*parent->dynamic_parsers) *
	       array_count(&dynamic_parsers));
	parent->struct_size = new_struct_size;
}

void settings_parser_info_update(pool_t pool,
				 const struct dynamic_settings_parser *parsers)
{
	if (parsers[0].name != NULL) T_BEGIN {
		info_update_real(pool, parsers);
	} T_END;
}

const void *settings_find_dynamic(struct setting_parser_info *info,
				  const void *base_set, const char *name)
{
	unsigned int i;

	if (info->dynamic_parsers == NULL)
		return NULL;

	for (i = 0; info->dynamic_parsers[i].name != NULL; i++) {
		if (strcmp(info->dynamic_parsers[i].name, name) == 0) {
			return CONST_PTR_OFFSET(base_set,
				info->dynamic_parsers[i].struct_offset);
		}
	}
	return NULL;
}

static struct setting_link *
settings_link_get_new(struct setting_parser_context *new_ctx,
		      struct hash_table *links,
		      struct setting_link *old_link)
{
	struct setting_link *new_link;
	void *const *old_sets, **new_sets;
	unsigned int i, count, count2;
	size_t diff;

	new_link = hash_table_lookup(links, old_link);
	if (new_link != NULL)
		return new_link;

	i_assert(old_link->parent != NULL);
	i_assert(old_link->array != NULL);

	new_link = p_new(new_ctx->parser_pool, struct setting_link, 1);
	new_link->info = old_link->info;
	new_link->parent = settings_link_get_new(new_ctx, links,
						 old_link->parent);

	/* find the array from parent struct */
	diff = (char *)old_link->array - (char *)old_link->parent->set_struct;
	i_assert(diff + sizeof(*old_link->array) <= old_link->parent->info->struct_size);
	new_link->array = PTR_OFFSET(new_link->parent->set_struct, diff);

	if (old_link->set_struct != NULL) {
		/* find our struct from array */
		old_sets = array_get(old_link->array, &count);
		new_sets = array_get_modifiable(new_link->array, &count2);
		i_assert(count == count2);
		for (i = 0; i < count; i++) {
			if (old_sets[i] == old_link->set_struct) {
				new_link->set_struct = new_sets[i];
				break;
			}
		}
		i_assert(i < count);
	}
	hash_table_insert(links, old_link, new_link);
	return new_link;
}

struct setting_parser_context *
settings_parser_dup(struct setting_parser_context *old_ctx, pool_t new_pool)
{
	struct setting_parser_context *new_ctx;
	struct hash_iterate_context *iter;
	struct setting_link *new_link;
	struct hash_table *links;
	void *key, *value;
	unsigned int i;
	pool_t parser_pool;

	pool_ref(new_pool);
	parser_pool = pool_alloconly_create("dup settings parser", 8192);
	new_ctx = p_new(parser_pool, struct setting_parser_context, 1);
	new_ctx->set_pool = new_pool;
	new_ctx->parser_pool = parser_pool;
	new_ctx->flags = old_ctx->flags;
	new_ctx->str_vars_are_expanded = old_ctx->str_vars_are_expanded;
	new_ctx->linenum = old_ctx->linenum;
	new_ctx->error = p_strdup(new_ctx->parser_pool, old_ctx->error);
	new_ctx->prev_info = old_ctx->prev_info;

	links = hash_table_create(default_pool, new_ctx->parser_pool,
				  0, NULL, NULL);

	new_ctx->root_count = old_ctx->root_count;
	new_ctx->roots = p_new(new_ctx->parser_pool, struct setting_link,
			       new_ctx->root_count);
	for (i = 0; i < new_ctx->root_count; i++) {
		i_assert(old_ctx->roots[i].parent == NULL);
		i_assert(old_ctx->roots[i].array == NULL);

		new_ctx->roots[i].info = old_ctx->roots[i].info;
		new_ctx->roots[i].set_struct =
			settings_dup(old_ctx->roots[i].info,
				     old_ctx->roots[i].set_struct,
				     new_ctx->set_pool);
		new_ctx->roots[i].change_struct =
			settings_changes_dup(old_ctx->roots[i].info,
					     old_ctx->roots[i].change_struct,
					     new_ctx->set_pool);
		hash_table_insert(links, &old_ctx->roots[i],
				  &new_ctx->roots[i]);
	}

	new_ctx->links =
		hash_table_create(default_pool, new_ctx->parser_pool, 0,
				  str_hash, (hash_cmp_callback_t *)strcmp);

	iter = hash_table_iterate_init(old_ctx->links);
	while (hash_table_iterate(iter, &key, &value)) {
		new_link = settings_link_get_new(new_ctx, links, value);
		hash_table_insert(new_ctx->links,
				  p_strdup(new_ctx->parser_pool, key),
				  new_link);
	}
	hash_table_iterate_deinit(&iter);
	hash_table_destroy(&links);
	return new_ctx;
}

static void *
settings_changes_init(const struct setting_parser_info *info,
		      const void *change_set, pool_t pool)
{
	const struct setting_define *def;
	const ARRAY_TYPE(void_array) *src_arr;
	ARRAY_TYPE(void_array) *dest_arr;
	void *dest_set, *set, *const *children;
	unsigned int i, count;

	dest_set = p_malloc(pool, info->struct_size);
	for (def = info->defines; def->key != NULL; def++) {
		if (def->type != SET_DEFLIST)
			continue;

		src_arr = CONST_PTR_OFFSET(change_set, def->offset);
		dest_arr = PTR_OFFSET(dest_set, def->offset);

		if (array_is_created(src_arr)) {
			children = array_get(src_arr, &count);
			i_assert(!array_is_created(dest_arr));
			p_array_init(dest_arr, pool, count);
			for (i = 0; i < count; i++) {
				set = settings_changes_init(def->list_info,
							    children[i], pool);
				array_append(dest_arr, &set, 1);
			}
		}
	}
	return dest_set;
}

static int
settings_apply(struct setting_link *dest_link,
	       const struct setting_link *src_link,
	       pool_t pool, const char **conflict_key_r)
{
	const struct setting_define *def;
	const void *src, *csrc;
	void *dest, *cdest, *const *children;
	unsigned int i, count;

	for (def = dest_link->info->defines; def->key != NULL; def++) {
		csrc = CONST_PTR_OFFSET(src_link->change_struct, def->offset);
		cdest = PTR_OFFSET(dest_link->change_struct, def->offset);

		if (def->type == SET_DEFLIST || def->type == SET_STRLIST) {
			/* just add the new values */
		} else if (*((const char *)csrc) == 0) {
			/* unchanged */
			continue;
		} else if (*((const char *)cdest) != 0) {
			/* conflict */
			if (conflict_key_r != NULL) {
				*conflict_key_r = def->key;
				return -1;
			}
			continue;
		} else {
			*((char *)cdest) = 1;
		}

		/* found a changed setting */
		src = CONST_PTR_OFFSET(src_link->set_struct, def->offset);
		dest = PTR_OFFSET(dest_link->set_struct, def->offset);

		if (!setting_copy(def->type, src, dest, pool)) {
			const ARRAY_TYPE(void_array) *src_arr = src;
			ARRAY_TYPE(void_array) *dest_arr = dest;
			void *child_set;

			if (!array_is_created(src_arr))
				continue;

			children = array_get(src_arr, &count);
			if (!array_is_created(dest_arr))
				p_array_init(dest_arr, pool, count);
			for (i = 0; i < count; i++) {
				child_set = settings_dup(def->list_info,
							 children[i], pool);
				array_append(dest_arr, &child_set, 1);
				settings_set_parent(def->list_info, child_set,
						    dest_link->set_struct);
			}

			/* copy changes */
			dest_arr = cdest;
			if (!array_is_created(dest_arr))
				p_array_init(dest_arr, pool, count);
			for (i = 0; i < count; i++) {
				child_set =
					settings_changes_init(def->list_info,
							      children[i],
							      pool);
				array_append(dest_arr, &child_set, 1);
			}
		}
	}
	return 0;
}

int settings_parser_apply_changes(struct setting_parser_context *dest,
				  const struct setting_parser_context *src,
				  pool_t pool, const char **conflict_key_r)
{
	unsigned int i;

	i_assert(src->root_count == dest->root_count);
	for (i = 0; i < dest->root_count; i++) {
		i_assert(src->roots[i].info == dest->roots[i].info);
		if (settings_apply(&dest->roots[i], &src->roots[i], pool,
				   conflict_key_r) < 0)
			return -1;
	}
	return 0;
}
