/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "hash.h"
#include "net.h"
#include "env-util.h"
#include "execv-const.h"
#include "str.h"
#include "strescape.h"
#include "str-parse.h"
#include "var-expand.h"
#include "settings-parser.h"

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>

#define IS_WHITE(c) ((c) == ' ' || (c) == '\t')

struct setting_link {
        struct setting_link *parent;
	const struct setting_parser_info *info;

	const char *full_key;

	/* Points to array inside parent->set_struct.
	   SET_STRLIST : array of const_strings */
	ARRAY_TYPE(void_array) *array;
	/* Pointer to structure containing the values */
	void *set_struct;
	/* Pointer to structure containing non-zero values for settings that
	   have been changed. */
	void *change_struct;
};

struct setting_parser_context {
	pool_t set_pool, parser_pool;
	int refcount;
        enum settings_parser_flags flags;
	bool str_vars_are_expanded;
	uint8_t change_counter;

	struct setting_link root;
	HASH_TABLE(char *, struct setting_link *) links;

	unsigned int linenum;
	char *error;
	const struct setting_parser_info *prev_info;
};

static const struct setting_parser_info strlist_info = {
	.name = NULL,
	.defines = NULL,
	.defaults = NULL,

	.struct_size = 0,
};

HASH_TABLE_DEFINE_TYPE(setting_link, struct setting_link *,
		       struct setting_link *);

static void
setting_parser_copy_defaults(struct setting_parser_context *ctx,
			     const struct setting_parser_info *info,
			     struct setting_link *link)
{
	const struct setting_define *def;
	const char *p, **strp;

	if (info->defaults == NULL)
		return;

	memcpy(link->set_struct, info->defaults, info->struct_size);
	for (def = info->defines; def->key != NULL; def++) {
		switch (def->type) {
		case SET_ENUM: {
			/* fix enums by dropping everything after the
			   first ':' */
			strp = STRUCT_MEMBER_P(link->set_struct, def->offset);
			p = strchr(*strp, ':');
			if (p != NULL)
				*strp = p_strdup_until(ctx->set_pool, *strp, p);
			break;
		}
		case SET_STR_VARS: {
			/* insert the unexpanded-character */
			strp = STRUCT_MEMBER_P(link->set_struct, def->offset);
			if (*strp != NULL) {
				*strp = p_strconcat(ctx->set_pool,
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

static void
setting_parser_fill_defaults_strings(struct setting_parser_context *ctx)
{
	const struct setting_keyvalue *defaults =
		ctx->root.info->default_settings;
	if (defaults == NULL)
		return;

	for (unsigned int i = 0; defaults[i].key != NULL; i++) {
		const char *key = defaults[i].key;
		const char *value = defaults[i].value;
		if (settings_parse_keyvalue_nodup(ctx, key, value) <= 0) {
			i_panic("Failed to add default setting %s=%s: %s",
				key, value, settings_parser_get_error(ctx));
		}
	}
}

struct setting_parser_context *
settings_parser_init(pool_t set_pool, const struct setting_parser_info *root,
		     enum settings_parser_flags flags)
{
	struct setting_parser_context *ctx;
	pool_t parser_pool;

	parser_pool = pool_alloconly_create(MEMPOOL_GROWING"settings parser",
					    1024);
	ctx = p_new(parser_pool, struct setting_parser_context, 1);
	ctx->refcount = 1;
	ctx->set_pool = set_pool;
	ctx->parser_pool = parser_pool;
	ctx->flags = flags;
	/* use case-insensitive comparisons. this is mainly because settings
	   may go through environment variables where their keys get
	   uppercased. of course the alternative would be to not uppercase
	   environment. probably doesn't make much difference which way is
	   chosen. */
	hash_table_create(&ctx->links, ctx->parser_pool, 0,
			  strcase_hash, strcasecmp);

	ctx->root.info = root;
	if (root->struct_size > 0) {
		ctx->root.set_struct =
			p_malloc(ctx->set_pool, root->struct_size);
		if ((flags & SETTINGS_PARSER_FLAG_TRACK_CHANGES) != 0) {
			ctx->change_counter = 1;
			ctx->root.change_struct =
				p_malloc(ctx->set_pool, root->struct_size);
		}
		setting_parser_copy_defaults(ctx, root, &ctx->root);
		setting_parser_fill_defaults_strings(ctx);
	}

	pool_ref(ctx->set_pool);
	return ctx;
}

void settings_parser_ref(struct setting_parser_context *ctx)
{
	i_assert(ctx->refcount > 0);
	ctx->refcount++;
}

void settings_parser_unref(struct setting_parser_context **_ctx)
{
	struct setting_parser_context *ctx = *_ctx;

	*_ctx = NULL;

	i_assert(ctx->refcount > 0);
	if (--ctx->refcount > 0)
		return;
	hash_table_destroy(&ctx->links);
	i_free(ctx->error);
	pool_unref(&ctx->set_pool);
	pool_unref(&ctx->parser_pool);
}

void *settings_parser_get_set(const struct setting_parser_context *ctx)
{
	return ctx->root.set_struct;
}

void *settings_parser_get_changes(struct setting_parser_context *ctx)
{
	return ctx->root.change_struct;
}

static void settings_parser_set_error(struct setting_parser_context *ctx,
				      const char *error)
{
	i_free(ctx->error);
	ctx->error = i_strdup(error);
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
	const char *error;
	int ret;
	if ((ret = str_parse_get_bool(value, result_r, &error)) < 0)
		settings_parser_set_error(ctx, error);
	return ret;
}

static int
get_uint(struct setting_parser_context *ctx, const char *value,
	 unsigned int *result_r)
{
	if (str_to_uint(value, result_r) < 0) {
		settings_parser_set_error(ctx, t_strdup_printf(
			"Invalid number %s: %s", value,
			str_num_error(value)));
		return -1;
	}
	return 0;
}

static int
get_octal(struct setting_parser_context *ctx, const char *value,
	  unsigned int *result_r)
{
	unsigned long long octal;

	if (*value != '0')
		return get_uint(ctx, value, result_r);

	if (str_to_ullong_oct(value, &octal) < 0) {
		settings_parser_set_error(ctx,
			t_strconcat("Invalid number: ", value, NULL));
		return -1;
	}
	*result_r = (unsigned int)octal;
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

			settings_parser_set_error(ctx,
				t_strconcat("Invalid value: ", value, NULL));
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

static int ATTR_NULL(2)
setting_link_add(struct setting_parser_context *ctx,
		 const struct setting_link *link_copy, char *key)
{
	struct setting_link *link;

	link = hash_table_lookup(ctx->links, key);
	if (link != NULL) {
		if (link->parent == link_copy->parent &&
		    link->info == link_copy->info)
			return 0;
		settings_parser_set_error(ctx,
			t_strconcat(key, " already exists", NULL));
		return -1;
	}

	link = p_new(ctx->parser_pool, struct setting_link, 1);
	*link = *link_copy;
	link->full_key = key;
	i_assert(hash_table_lookup(ctx->links, key) == NULL);
	hash_table_insert(ctx->links, key, link);
	return 0;
}

static int ATTR_NULL(3, 8)
get_strlist(struct setting_parser_context *ctx, struct setting_link *parent,
	    const char *key, const char *value, ARRAY_TYPE(void_array) *result)
{
	struct setting_link new_link;
	const char *const *list;
	char *full_key;

	if (!array_is_created(result))
		p_array_init(result, ctx->set_pool, 5);

	i_zero(&new_link);
	new_link.parent = parent;
	new_link.info = &strlist_info;
	new_link.array = result;

	/* there are no sections below strlist, so allow referencing it
	   without the key (e.g. plugin/foo instead of plugin/0/foo) */
	full_key = p_strdup(ctx->parser_pool, key);
	if (setting_link_add(ctx, &new_link, full_key) < 0)
		return -1;

	list = t_strsplit(value, ",\t ");
	for (; *list != NULL; list++) {
		if (**list == '\0')
			continue;

		full_key = p_strconcat(ctx->parser_pool, key,
				       SETTINGS_SEPARATOR_S, *list, NULL);
		if (setting_link_add(ctx, &new_link, full_key) < 0)
			return -1;
	}
	return 0;
}

static int
get_in_port_zero(struct setting_parser_context *ctx, const char *value,
	 in_port_t *result_r)
{
	if (net_str2port_zero(value, result_r) < 0) {
		settings_parser_set_error(ctx, t_strdup_printf(
			"Invalid port number %s", value));
		return -1;
	}
	return 0;
}

static void
settings_parse_strlist(struct setting_parser_context *ctx,
		       struct setting_link *link,
		       const char *key, const char *value)
{
	void *const *items;
	void *vkey, *vvalue;
	unsigned int i, count;

	key = strrchr(key, SETTINGS_SEPARATOR) + 1;
	vvalue = p_strdup(ctx->set_pool, value);

	/* replace if it already exists */
	items = array_get(link->array, &count);
	for (i = 0; i < count; i += 2) {
		if (strcmp(items[i], key) == 0) {
			array_idx_set(link->array, i + 1, &vvalue);
			return;
		}
	}

	vkey = p_strdup(ctx->set_pool, key);
	array_push_back(link->array, &vkey);
	array_push_back(link->array, &vvalue);
}

static int
settings_parse(struct setting_parser_context *ctx, struct setting_link *link,
	       const struct setting_define *def,
	       const char *key, const char *value, bool dup_value)
{
	void *ptr, *change_ptr;
	const void *ptr2;
	const char *error;

	while (def->type == SET_ALIAS) {
		i_assert(def != link->info->defines);
		def--;
	}

	ctx->prev_info = link->info;

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
	case SET_UINT_OCT:
		if (get_octal(ctx, value, (unsigned int *)ptr) < 0)
			return -1;
		break;
	case SET_TIME:
		if (str_parse_get_interval(value, (unsigned int *)ptr, &error) < 0) {
			settings_parser_set_error(ctx, error);
			return -1;
		}
		break;
	case SET_TIME_MSECS:
		if (str_parse_get_interval_msecs(value, (unsigned int *)ptr, &error) < 0) {
			settings_parser_set_error(ctx, error);
			return -1;
		}
		break;
	case SET_SIZE:
		if (str_parse_get_size(value, (uoff_t *)ptr, &error) < 0) {
			settings_parser_set_error(ctx, error);
			return -1;
		}
		break;
	case SET_IN_PORT:
		if (get_in_port_zero(ctx, value, (in_port_t *)ptr) < 0)
			return -1;
		break;
	case SET_STR:
		if (dup_value)
			value = p_strdup(ctx->set_pool, value);
		*((const char **)ptr) = value;
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
		ptr2 = CONST_STRUCT_MEMBER_P(link->info->defaults, def->offset);
		if (get_enum(ctx, value, (char **)ptr,
			     *(const char *const *)ptr2) < 0)
			return -1;
		break;
	case SET_STRLIST: {
		ctx->prev_info = &strlist_info;
		if (get_strlist(ctx, link, key, value,
				(ARRAY_TYPE(void_array) *)ptr) < 0)
			return -1;
		break;
	}
	case SET_FILTER_ARRAY: {
		/* Add filter names to the array. Userdb can add more simply
		   by giving e.g. "namespace=newname" without it removing the
		   existing ones. */
		ARRAY_TYPE(const_string) *arr = ptr;
		const char *const *list = t_strsplit(value, ",\t ");
		unsigned int i, count = str_array_length(list);
		if (!array_is_created(arr))
			p_array_init(arr, ctx->set_pool, count);
		for (i = 0; i < count; i++) {
			const char *value = p_strdup(ctx->set_pool,
				settings_section_unescape(list[i]));
			array_push_back(arr, &value);
		}
		break;
	}
	case SET_FILTER_NAME:
		settings_parser_set_error(ctx, t_strdup_printf(
			"Setting is a named filter, use '%s {'", key));
		return -1;
	case SET_ALIAS:
		i_unreached();
	}

	if (change_ptr != NULL) {
		uint8_t *change_ptr8 = change_ptr;
		if (*change_ptr8 < ctx->change_counter)
			*change_ptr8 = ctx->change_counter;
	}
	return 0;
}

static bool
settings_find_key_nth(struct setting_parser_context *ctx, const char *key,
		      bool allow_filter_name, unsigned int *n,
		      const struct setting_define **def_r,
		      struct setting_link **link_r)
{
	const struct setting_define *def;
	struct setting_link *link;
	const char *end, *parent_key;

	/* try to find from roots */
	if (*n == 0) {
		def = setting_define_find(ctx->root.info, key);
		if (def != NULL && (def->type != SET_FILTER_NAME ||
				    allow_filter_name)) {
			*n = 1;
			*def_r = def;
			*link_r = &ctx->root;
			return TRUE;
		}
	}
	if (*n > 1)
		return FALSE;
	*n += 1;

	/* try to find from links */
	end = strrchr(key, SETTINGS_SEPARATOR);
	if (end == NULL)
		return FALSE;

	parent_key = t_strdup_until(key, end);
	link = hash_table_lookup(ctx->links, parent_key);
	if (link == NULL) {
		/* maybe this is the first strlist value */
		unsigned int parent_n = 0;
		const struct setting_define *parent_def;
		struct setting_link *parent_link;

		if (!settings_find_key_nth(ctx, parent_key, FALSE, &parent_n,
					   &parent_def, &parent_link))
			return FALSE;
		if (parent_def == NULL) {
			/* we'll get here with e.g. "plugin/a/b=val".
			   not sure if we should ever do anything here.. */
			if (parent_link->full_key == NULL ||
			    strcmp(parent_link->full_key, parent_key) != 0)
				return FALSE;
		} else {
			if (parent_def->type != SET_STRLIST)
				return FALSE;
		}

		/* setting parent_key=0 adds it to links list */
		if (settings_parse_keyvalue(ctx, parent_key, "0") <= 0)
			return FALSE;

		link = hash_table_lookup(ctx->links, parent_key);
		i_assert(link != NULL);
	}

	*link_r = link;
	i_assert(link->info == &strlist_info);
	*def_r = NULL;
	return TRUE;
}

static bool
settings_find_key(struct setting_parser_context *ctx, const char *key,
		  bool allow_filter_name, const struct setting_define **def_r,
		  struct setting_link **link_r)
{
	unsigned int n = 0;

	return settings_find_key_nth(ctx, key, allow_filter_name,
				     &n, def_r, link_r);
}

const struct setting_define *
settings_parse_get_filter(struct setting_parser_context *ctx,
			  const char *filter_name)
{
	const struct setting_define *def;
	struct setting_link *link;

	if (!settings_find_key(ctx, filter_name, TRUE, &def, &link))
		return NULL;
	if (def->type != SET_FILTER_NAME && def->type != SET_FILTER_ARRAY)
		return NULL;
	return def;
}

static int
settings_parse_keyvalue_real(struct setting_parser_context *ctx,
			     const char *key, const char *value, bool dup_value)
{
	const struct setting_define *def;
	struct setting_link *link;
	unsigned int n = 0;

	i_free(ctx->error);
	ctx->prev_info = NULL;

	if (!settings_find_key_nth(ctx, key, FALSE, &n, &def, &link)) {
		settings_parser_set_error(ctx,
			t_strconcat("Unknown setting: ", key, NULL));
		return 0;
	}

	do {
		if (def == NULL) {
			i_assert(link->info == &strlist_info);
			settings_parse_strlist(ctx, link, key, value);
			return 1;
		}

		if (settings_parse(ctx, link, def, key, value, dup_value) < 0)
			return -1;
		/* there may be more instances of the setting */
	} while (settings_find_key_nth(ctx, key, FALSE, &n, &def, &link));
	return 1;
}

int settings_parse_keyvalue(struct setting_parser_context *ctx,
			    const char *key, const char *value)
{
	return settings_parse_keyvalue_real(ctx, key, value, TRUE);
}

int settings_parse_keyvalue_nodup(struct setting_parser_context *ctx,
				  const char *key, const char *value)
{
	return settings_parse_keyvalue_real(ctx, key, value, FALSE);
}

const char *settings_parse_unalias(struct setting_parser_context *ctx,
				   const char *key)
{
	const struct setting_define *def;
	struct setting_link *link;

	if (!settings_find_key(ctx, key, FALSE, &def, &link))
		return NULL;
	if (def == NULL) {
		/* strlist */
		i_assert(link->info == &strlist_info);
		return key;
	}

	while (def->type == SET_ALIAS) {
		i_assert(def != link->info->defines);
		def--;
	}
	return def->key;
}

const void *
settings_parse_get_value(struct setting_parser_context *ctx,
			 const char *key, enum setting_type *type_r)
{
	const struct setting_define *def;
	struct setting_link *link;

	if (!settings_find_key(ctx, key, TRUE, &def, &link))
		return NULL;
	if (link->set_struct == NULL || def == NULL)
		return NULL;

	*type_r = def->type;
	return STRUCT_MEMBER_P(link->set_struct, def->offset);
}

void settings_parse_set_change_counter(struct setting_parser_context *ctx,
				       uint8_t change_counter)
{
	i_assert(change_counter > 0);
	i_assert((ctx->flags & SETTINGS_PARSER_FLAG_TRACK_CHANGES) != 0);
	ctx->change_counter = change_counter;
}

uint8_t settings_parse_get_change_counter(struct setting_parser_context *ctx,
					  const char *key)
{
	const struct setting_define *def;
	struct setting_link *link;
	const uint8_t *p;

	if (!settings_find_key(ctx, key, FALSE, &def, &link))
		return 0;
	if (link->change_struct == NULL || def == NULL)
		return 0;

	p = STRUCT_MEMBER_P(link->change_struct, def->offset);
	return *p;
}

int settings_parse_line(struct setting_parser_context *ctx, const char *line)
{
	const char *key, *value;
	int ret;

	key = line;
	value = strchr(line, '=');
	if (value == NULL) {
		settings_parser_set_error(ctx, "Missing '='");
		return -1;
	}

	if (key == value) {
		settings_parser_set_error(ctx,
			"Missing key name ('=' at the beginning of line)");
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

bool settings_check(struct event *event, const struct setting_parser_info *info,
		    pool_t pool, void *set, const char **error_r)
{
	bool valid;

	if (info->check_func != NULL) {
		T_BEGIN {
			valid = info->check_func(set, pool, error_r);
		} T_END_PASS_STR_IF(!valid, error_r);
		if (!valid)
			return FALSE;
	}
	if (info->ext_check_func != NULL) {
		T_BEGIN {
			valid = info->ext_check_func(event, set, pool, error_r);
		} T_END_PASS_STR_IF(!valid, error_r);
		if (!valid)
			return FALSE;
	}
	return TRUE;
}

bool settings_parser_check(struct setting_parser_context *ctx, pool_t pool,
			   struct event *event, const char **error_r)
{
	return settings_check(event, ctx->root.info, pool,
			      ctx->root.set_struct, error_r);
}

void settings_parse_set_expanded(struct setting_parser_context *ctx,
				 bool is_expanded)
{
	ctx->str_vars_are_expanded = is_expanded;
}

static int ATTR_NULL(3, 4, 5)
settings_var_expand_info(const struct setting_parser_info *info, void *set,
			 pool_t pool,
			 const struct var_expand_table *table,
			 const struct var_expand_func_table *func_table,
			 void *func_context, string_t *str,
			 const char **error_r)
{
	const struct setting_define *def;
	void *value;
	const char *error;
	int ret, final_ret = 1;

	for (def = info->defines; def->key != NULL; def++) {
		value = PTR_OFFSET(set, def->offset);
		switch (def->type) {
		case SET_BOOL:
		case SET_UINT:
		case SET_UINT_OCT:
		case SET_TIME:
		case SET_TIME_MSECS:
		case SET_SIZE:
		case SET_IN_PORT:
		case SET_STR:
		case SET_ENUM:
		case SET_STRLIST:
		case SET_FILTER_NAME:
		case SET_FILTER_ARRAY:
		case SET_ALIAS:
			break;
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
				ret = var_expand_with_funcs(str, *val + 1, table,
							    func_table, func_context,
							    &error);
				if (final_ret > ret) {
					final_ret = ret;
					*error_r = t_strdup_printf(
						"%s: %s", def->key, error);
				}
				*val = p_strdup(pool, str_c(str));
			} else {
				i_assert(**val == SETTING_STRVAR_EXPANDED[0]);
				*val += 1;
			}
			break;
		}
		}
	}

	if (final_ret <= 0)
		return final_ret;

	if (info->expand_check_func != NULL) {
		if (!info->expand_check_func(set, pool, error_r))
			return -1;
	}

	return final_ret;
}

int settings_var_expand(const struct setting_parser_info *info,
			void *set, pool_t pool,
			const struct var_expand_table *table,
			const char **error_r)
{
	return settings_var_expand_with_funcs(info, set, pool, table,
					      NULL, NULL, error_r);
}

int settings_var_expand_with_funcs(const struct setting_parser_info *info,
				   void *set, pool_t pool,
				   const struct var_expand_table *table,
				   const struct var_expand_func_table *func_table,
				   void *func_context, const char **error_r)
{
	int ret;

	T_BEGIN {
		string_t *str = t_str_new(256);

		ret = settings_var_expand_info(info, set, pool, table,
					       func_table, func_context, str,
					       error_r);
	} T_END_PASS_STR_IF(ret <= 0, error_r);
	return ret;
}

void settings_parse_var_skip(struct setting_parser_context *ctx)
{
	settings_var_skip(ctx->root.info, ctx->root.set_struct);
}

void settings_var_skip(const struct setting_parser_info *info, void *set)
{
	const char *error;

	(void)settings_var_expand_info(info, set, NULL, NULL, NULL, NULL, NULL,
				       &error);
}

static void
setting_copy(enum setting_type type, const void *src, void *dest, pool_t pool,
	     bool keep_values)
{
	switch (type) {
	case SET_BOOL: {
		const bool *src_bool = src;
		bool *dest_bool = dest;

		*dest_bool = *src_bool;
		break;
	}
	case SET_UINT:
	case SET_UINT_OCT:
	case SET_TIME:
	case SET_TIME_MSECS: {
		const unsigned int *src_uint = src;
		unsigned int *dest_uint = dest;

		*dest_uint = *src_uint;
		break;
	}
	case SET_SIZE: {
		const uoff_t *src_size = src;
		uoff_t *dest_size = dest;

		*dest_size = *src_size;
		break;
	}
	case SET_IN_PORT: {
		const in_port_t *src_size = src;
		in_port_t *dest_size = dest;

		*dest_size = *src_size;
		break;
	}
	case SET_STR_VARS:
	case SET_STR:
	case SET_ENUM: {
		const char *const *src_str = src;
		const char **dest_str = dest;

		if (keep_values)
			*dest_str = *src_str;
		else
			*dest_str = p_strdup(pool, *src_str);
		break;
	}
	case SET_STRLIST: {
		const ARRAY_TYPE(const_string) *src_arr = src;
		ARRAY_TYPE(const_string) *dest_arr = dest;
		const char *const *strings, *const *dest_strings, *dup;
		unsigned int i, j, count, dest_count;

		if (!array_is_created(src_arr))
			break;

		strings = array_get(src_arr, &count);
		i_assert(count % 2 == 0);
		if (!array_is_created(dest_arr))
			p_array_init(dest_arr, pool, count);
		dest_count = array_count(dest_arr);
		i_assert(dest_count % 2 == 0);
		for (i = 0; i < count; i += 2) {
			if (dest_count > 0) {
				dest_strings = array_front(dest_arr);
				for (j = 0; j < dest_count; j += 2) {
					if (strcmp(strings[i], dest_strings[j]) == 0)
						break;
				}
				if (j < dest_count)
					continue;
			}
			dup = keep_values ? strings[i] : p_strdup(pool, strings[i]);
			array_push_back(dest_arr, &dup);
			dup = keep_values ? strings[i+1] : p_strdup(pool, strings[i+1]);
			array_push_back(dest_arr, &dup);
		}
		break;
	}
	case SET_FILTER_ARRAY: {
		const ARRAY_TYPE(const_string) *src_arr = src;
		ARRAY_TYPE(const_string) *dest_arr = dest;
		const char *const *strings, *const *dest_strings, *dup;
		unsigned int i, j, count, dest_count;

		if (!array_is_created(src_arr))
			break;

		strings = array_get(src_arr, &count);
		if (!array_is_created(dest_arr))
			p_array_init(dest_arr, pool, count);
		dest_count = array_count(dest_arr);
		for (i = 0; i < count; i++) {
			if (dest_count > 0) {
				dest_strings = array_front(dest_arr);
				for (j = 0; j < dest_count; j++) {
					if (strcmp(strings[i], dest_strings[j]) == 0)
						break;
				}
				if (j < dest_count)
					continue;
			}
			dup = keep_values ? strings[i] : p_strdup(pool, strings[i]);
			array_push_back(dest_arr, &dup);
		}
		break;
	}
	case SET_FILTER_NAME:
	case SET_ALIAS:
		break;
	}
}

static void *settings_dup_full(const struct setting_parser_info *info,
			       const void *set, pool_t pool, bool keep_values)
{
	const struct setting_define *def;
	const void *src;
	void *dest_set, *dest;

	if (info->struct_size == 0)
		return NULL;

	/* don't just copy everything from set to dest_set. it may contain
	   some non-setting fields allocated from the original pool. */
	dest_set = p_malloc(pool, info->struct_size);
	for (def = info->defines; def->key != NULL; def++) {
		src = CONST_PTR_OFFSET(set, def->offset);
		dest = PTR_OFFSET(dest_set, def->offset);

		setting_copy(def->type, src, dest, pool, keep_values);
	}

	if (info->pool_offset1 > 0) {
		pool_t *pool_p = PTR_OFFSET(dest_set, info->pool_offset1 - 1);
		*pool_p = pool;
	}
	return dest_set;
}

static void *
settings_changes_dup(const struct setting_parser_info *info,
		     const void *change_set, pool_t pool)
{
	const struct setting_define *def;
	const void *src;
	void *dest_set, *dest;

	if (change_set == NULL || info->struct_size == 0)
		return NULL;

	dest_set = p_malloc(pool, info->struct_size);
	for (def = info->defines; def->key != NULL; def++) {
		src = CONST_PTR_OFFSET(change_set, def->offset);
		dest = PTR_OFFSET(dest_set, def->offset);

		switch (def->type) {
		case SET_BOOL:
		case SET_UINT:
		case SET_UINT_OCT:
		case SET_TIME:
		case SET_TIME_MSECS:
		case SET_SIZE:
		case SET_IN_PORT:
		case SET_STR_VARS:
		case SET_STR:
		case SET_ENUM:
		case SET_STRLIST:
		case SET_FILTER_ARRAY:
			*((uint8_t *)dest) = *((const uint8_t *)src);
			break;
		case SET_FILTER_NAME:
		case SET_ALIAS:
			break;
		}
	}
	return dest_set;
}

static struct setting_link *
settings_link_get_new(struct setting_parser_context *new_ctx,
		      HASH_TABLE_TYPE(setting_link) links,
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
	i_assert(hash_table_lookup(links, old_link) == NULL);
	hash_table_insert(links, old_link, new_link);
	return new_link;
}

struct setting_parser_context *
settings_parser_dup(const struct setting_parser_context *old_ctx,
		    pool_t new_pool)
{
	struct setting_parser_context *new_ctx;
	struct hash_iterate_context *iter;
	HASH_TABLE_TYPE(setting_link) links;
	struct setting_link *new_link, *value;
	char *key;
	pool_t parser_pool;
	bool keep_values;

	/* if source and destination pools are the same, there's no need to
	   duplicate values */
	keep_values = new_pool == old_ctx->set_pool;

	pool_ref(new_pool);
	parser_pool = pool_alloconly_create(MEMPOOL_GROWING"dup settings parser",
					    1024);
	new_ctx = p_new(parser_pool, struct setting_parser_context, 1);
	new_ctx->refcount = 1;
	new_ctx->set_pool = new_pool;
	new_ctx->parser_pool = parser_pool;
	new_ctx->flags = old_ctx->flags;
	new_ctx->str_vars_are_expanded = old_ctx->str_vars_are_expanded;
	new_ctx->linenum = old_ctx->linenum;
	new_ctx->error = i_strdup(old_ctx->error);
	new_ctx->prev_info = old_ctx->prev_info;

	hash_table_create_direct(&links, new_ctx->parser_pool, 0);

	i_assert(old_ctx->root.parent == NULL);
	i_assert(old_ctx->root.array == NULL);

	new_ctx->root.info = old_ctx->root.info;
	new_ctx->root.set_struct =
		settings_dup_full(old_ctx->root.info,
				  old_ctx->root.set_struct,
				  new_ctx->set_pool, keep_values);
	new_ctx->root.change_struct =
		settings_changes_dup(old_ctx->root.info,
				     old_ctx->root.change_struct,
				     new_ctx->set_pool);
	struct setting_link *old_link = (struct setting_link *)&old_ctx->root;
	hash_table_insert(links, old_link, &new_ctx->root);

	hash_table_create(&new_ctx->links, new_ctx->parser_pool, 0,
			  strcase_hash, strcasecmp);

	iter = hash_table_iterate_init(old_ctx->links);
	while (hash_table_iterate(iter, old_ctx->links, &key, &value)) {
		new_link = settings_link_get_new(new_ctx, links, value);
		key = p_strdup(new_ctx->parser_pool, key);
		hash_table_insert(new_ctx->links, key, new_link);
	}
	hash_table_iterate_deinit(&iter);
	hash_table_destroy(&links);
	return new_ctx;
}

const char *settings_section_escape(const char *name)
{
#define CHAR_NEED_ESCAPE(c) \
	((c) == '=' || (c) == SETTINGS_SEPARATOR || (c) == '\\' || (c) == ' ' || (c) == ',')
	string_t *str;
	unsigned int i;

	for (i = 0; name[i] != '\0'; i++) {
		if (CHAR_NEED_ESCAPE(name[i]))
			break;
	}
	if (name[i] == '\0') {
		if (i == 0)
			return "\\.";
		return name;
	}

	str = t_str_new(i + strlen(name+i) + 8);
	str_append_data(str, name, i);
	for (; name[i] != '\0'; i++) {
		switch (name[i]) {
		case '=':
			str_append(str, "\\e");
			break;
		case SETTINGS_SEPARATOR:
			str_append(str, "\\s");
			break;
		case '\\':
			str_append(str, "\\\\");
			break;
		case ' ':
			str_append(str, "\\_");
			break;
		case ',':
			str_append(str, "\\+");
			break;
		default:
			str_append_c(str, name[i]);
			break;
		}
	}
	return str_c(str);
}

const char *settings_section_unescape(const char *name)
{
	const char *p = strchr(name, '\\');
	if (p == NULL)
		return name;

	string_t *str = t_str_new(strlen(name));
	str_append_data(str, name, p - name);
	while (p[1] != '\0') {
		switch (p[1]) {
		case 'e':
			str_append_c(str, '=');
			break;
		case 's':
			str_append_c(str, SETTINGS_SEPARATOR);
			break;
		case '\\':
			str_append_c(str, '\\');
			break;
		case '_':
			str_append_c(str, ' ');
			break;
		case '+':
			str_append_c(str, ',');
			break;
		case '.':
			/* empty string */
			break;
		default:
			/* not supposed to happen */
			str_append_c(str, '\\');
			str_append_c(str, p[1]);
			break;
		}
		name = p+2;
		p = strchr(name, '\\');
		if (p == NULL) {
			str_append(str, name);
			return str_c(str);
		}
		str_append_data(str, name, p - name);
	}
	/* ends with '\\' - not supposed to happen */
	str_append_c(str, '\\');
	return str_c(str);
}

static bool config_binary = FALSE;

bool is_config_binary(void)
{
	return config_binary;
}

void set_config_binary(bool value)
{
	config_binary = value;
}

