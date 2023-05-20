/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
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

struct setting_parser_context {
	pool_t set_pool, parser_pool;
	int refcount;
        enum settings_parser_flags flags;
	bool str_vars_are_expanded;
	uint8_t change_counter;

	const struct setting_parser_info *info;

	/* Pointer to structure containing the values */
	void *set_struct;
	/* Pointer to structure containing non-zero values for settings that
	   have been changed. */
	void *change_struct;

	unsigned int linenum;
	char *error;
};

static void
setting_parser_copy_defaults(struct setting_parser_context *ctx,
			     const struct setting_parser_info *info)
{
	const struct setting_define *def;
	const char *p, **strp;

	if (info->defaults == NULL)
		return;

	memcpy(ctx->set_struct, info->defaults, info->struct_size);
	for (def = info->defines; def->key != NULL; def++) {
		switch (def->type) {
		case SET_ENUM: {
			/* fix enums by dropping everything after the
			   first ':' */
			strp = STRUCT_MEMBER_P(ctx->set_struct, def->offset);
			p = strchr(*strp, ':');
			if (p != NULL)
				*strp = p_strdup_until(ctx->set_pool, *strp, p);
			break;
		}
		case SET_STR_VARS: {
			/* insert the unexpanded-character */
			strp = STRUCT_MEMBER_P(ctx->set_struct, def->offset);
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
	const struct setting_keyvalue *defaults = ctx->info->default_settings;
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

	ctx->info = root;
	if (root->struct_size > 0) {
		ctx->set_struct =
			p_malloc(ctx->set_pool, root->struct_size);
		if ((flags & SETTINGS_PARSER_FLAG_TRACK_CHANGES) != 0) {
			ctx->change_counter = 1;
			ctx->change_struct =
				p_malloc(ctx->set_pool, root->struct_size);
		}
		setting_parser_copy_defaults(ctx, root);
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

	if (ctx == NULL)
		return;
	*_ctx = NULL;

	i_assert(ctx->refcount > 0);
	if (--ctx->refcount > 0)
		return;
	i_free(ctx->error);
	pool_unref(&ctx->set_pool);
	pool_unref(&ctx->parser_pool);
}

void *settings_parser_get_set(const struct setting_parser_context *ctx)
{
	return ctx->set_struct;
}

void *settings_parser_get_changes(struct setting_parser_context *ctx)
{
	return ctx->change_struct;
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
		       ARRAY_TYPE(const_string) *array,
		       const char *key, const char *value)
{
	const char *const *items;
	const char *vkey, *vvalue;
	unsigned int i, count;

	key = strrchr(key, SETTINGS_SEPARATOR);
	if (key == NULL)
		return;
	key++;
	vvalue = p_strdup(ctx->set_pool, value);

	if (!array_is_created(array))
		p_array_init(array, ctx->set_pool, 4);

	/* replace if it already exists */
	items = array_get(array, &count);
	for (i = 0; i < count; i += 2) {
		if (strcmp(items[i], key) == 0) {
			array_idx_set(array, i + 1, &vvalue);
			return;
		}
	}

	vkey = p_strdup(ctx->set_pool, key);
	array_push_back(array, &vkey);
	array_push_back(array, &vvalue);
}

static int
settings_parse(struct setting_parser_context *ctx,
	       const struct setting_define *def,
	       const char *key, const char *value, bool dup_value)
{
	void *ptr, *change_ptr;
	const void *ptr2;
	const char *error;

	i_free(ctx->error);

	while (def->type == SET_ALIAS) {
		i_assert(def != ctx->info->defines);
		def--;
	}

	change_ptr = ctx->change_struct == NULL ? NULL :
		STRUCT_MEMBER_P(ctx->change_struct, def->offset);

	ptr = STRUCT_MEMBER_P(ctx->set_struct, def->offset);
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
		i_assert(ctx->info->defaults != NULL);
		ptr2 = CONST_STRUCT_MEMBER_P(ctx->info->defaults, def->offset);
		if (get_enum(ctx, value, (char **)ptr,
			     *(const char *const *)ptr2) < 0)
			return -1;
		break;
	case SET_STRLIST:
		settings_parse_strlist(ctx, ptr, key, value);
		break;
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
settings_find_key(struct setting_parser_context *ctx, const char *key,
		  bool allow_filter_name, const struct setting_define **def_r)
{
	const struct setting_define *def;
	const char *end, *parent_key;

	/* try to find the exact key */
	def = setting_define_find(ctx->info, key);
	if (def != NULL && (def->type != SET_FILTER_NAME ||
			    allow_filter_name)) {
		*def_r = def;
		return TRUE;
	}

	/* try to find strlist/key prefix */
	end = strrchr(key, SETTINGS_SEPARATOR);
	if (end == NULL)
		return FALSE;

	parent_key = t_strdup_until(key, end);
	def = setting_define_find(ctx->info, parent_key);
	if (def != NULL && def->type == SET_STRLIST) {
		*def_r = def;
		return TRUE;
	}
	return FALSE;
}

static int
settings_parse_keyvalue_real(struct setting_parser_context *ctx,
			     const char *key, const char *value, bool dup_value)
{
	const struct setting_define *def;

	if (!settings_find_key(ctx, key, FALSE, &def)) {
		settings_parser_set_error(ctx,
			t_strconcat("Unknown setting: ", key, NULL));
		return 0;
	}

	if (settings_parse(ctx, def, key, value, dup_value) < 0)
		return -1;
	return 1;
}

int settings_parse_keyvalue(struct setting_parser_context *ctx,
			    const char *key, const char *value)
{
	return settings_parse_keyvalue_real(ctx, key, value, TRUE);
}

int settings_parse_keyidx_value(struct setting_parser_context *ctx,
				unsigned int key_idx, const char *key,
				const char *value)
{
	return settings_parse(ctx, &ctx->info->defines[key_idx],
			      key, value, TRUE);
}

int settings_parse_keyvalue_nodup(struct setting_parser_context *ctx,
				  const char *key, const char *value)
{
	return settings_parse_keyvalue_real(ctx, key, value, FALSE);
}

int settings_parse_keyidx_value_nodup(struct setting_parser_context *ctx,
				      unsigned int key_idx, const char *key,
				      const char *value)
{
	return settings_parse(ctx, &ctx->info->defines[key_idx],
			      key, value, FALSE);
}

const void *
settings_parse_get_value(struct setting_parser_context *ctx,
			 const char **key, enum setting_type *type_r)
{
	const struct setting_define *def;

	if (!settings_find_key(ctx, *key, TRUE, &def))
		return NULL;

	while (def->type == SET_ALIAS) {
		i_assert(def != ctx->info->defines);
		def--;
		/* Replace the key with the unaliased key. We assume here that
		   strlists don't have aliases, because the key replacement
		   would only need to replace the key prefix then. */
		i_assert(def->type != SET_STRLIST);
		*key = def->key;
	}
	*type_r = def->type;
	return STRUCT_MEMBER_P(ctx->set_struct, def->offset);
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
	const uint8_t *p;

	if (!settings_find_key(ctx, key, FALSE, &def))
		return 0;
	if (ctx->change_struct == NULL)
		return 0;

	p = STRUCT_MEMBER_P(ctx->change_struct, def->offset);
	return *p;
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
	return settings_check(event, ctx->info, pool,
			      ctx->set_struct, error_r);
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
	settings_var_skip(ctx->info, ctx->set_struct);
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

	i_assert(info->pool_offset1 > 0);
	pool_t *pool_p = PTR_OFFSET(dest_set, info->pool_offset1 - 1);
	*pool_p = pool;
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

struct setting_parser_context *
settings_parser_dup(const struct setting_parser_context *old_ctx,
		    pool_t new_pool)
{
	struct setting_parser_context *new_ctx;
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

	new_ctx->info = old_ctx->info;
	new_ctx->set_struct =
		settings_dup_full(old_ctx->info,
				  old_ctx->set_struct,
				  new_ctx->set_pool, keep_values);
	new_ctx->change_struct =
		settings_changes_dup(old_ctx->info,
				     old_ctx->change_struct,
				     new_ctx->set_pool);
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

