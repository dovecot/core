/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "hash.h"
#include "net.h"
#include "istream.h"
#include "env-util.h"
#include "execv-const.h"
#include "str.h"
#include "strescape.h"
#include "var-expand.h"
#include "settings-parser.h"

#include <stdio.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>

#define IS_WHITE(c) ((c) == ' ' || (c) == '\t')

struct setting_link {
        struct setting_link *parent;
	const struct setting_parser_info *info;

	const char *full_key;

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
	HASH_TABLE(char *, struct setting_link *) links;

	unsigned int linenum;
	const char *error;
	const struct setting_parser_info *prev_info;
};

static const struct setting_parser_info strlist_info = {
	.module_name = NULL,
	.defines = NULL,
	.defaults = NULL,

	.type_offset = (size_t)-1,
	.struct_size = 0,

	.parent_offset = (size_t)-1
};

HASH_TABLE_DEFINE_TYPE(setting_link, struct setting_link *,
		       struct setting_link *);

static void
setting_parser_copy_defaults(struct setting_parser_context *ctx, 
			     const struct setting_parser_info *info,
			     struct setting_link *link);
static int
settings_apply(struct setting_link *dest_link,
	       const struct setting_link *src_link,
	       pool_t pool, const char **conflict_key_r);

struct setting_parser_context *
settings_parser_init(pool_t set_pool, const struct setting_parser_info *root,
		     enum settings_parser_flags flags)
{
        return settings_parser_init_list(set_pool, &root, 1, flags);
}

static void
copy_unique_defaults(struct setting_parser_context *ctx, 
		     const struct setting_define *def,
		     struct setting_link *link)
{
	ARRAY_TYPE(void_array) *arr =
		STRUCT_MEMBER_P(link->set_struct, def->offset);
	ARRAY_TYPE(void_array) *carr = NULL;
	struct setting_link *new_link;
	struct setting_parser_info info;
	const char *const *keyp, *key, *prefix;
	void *const *children;
	void *new_set, *new_changes = NULL;
	char *full_key;
	unsigned int i, count;

	if (!array_is_created(arr))
		return;

	children = array_get(arr, &count);
	if (link->change_struct != NULL) {
		carr = STRUCT_MEMBER_P(link->change_struct, def->offset);
		i_assert(!array_is_created(carr));
		p_array_init(carr, ctx->set_pool, count + 4);
	}
	p_array_init(arr, ctx->set_pool, count + 4);

	i_zero(&info);
	info = *def->list_info;

	for (i = 0; i < count; i++) T_BEGIN {
		new_set = p_malloc(ctx->set_pool, info.struct_size);
		array_push_back(arr, &new_set);

		if (link->change_struct != NULL) {
			i_assert(carr != NULL);
			new_changes = p_malloc(ctx->set_pool, info.struct_size);
			array_push_back(carr, &new_changes);
		}

		keyp = CONST_PTR_OFFSET(children[i], info.type_offset);
		key = settings_section_escape(*keyp);

		new_link = p_new(ctx->set_pool, struct setting_link, 1);
		prefix = link->full_key == NULL ?
			t_strconcat(def->key, SETTINGS_SEPARATOR_S, NULL) :
			t_strconcat(link->full_key, SETTINGS_SEPARATOR_S,
				    def->key, SETTINGS_SEPARATOR_S,NULL);
		full_key = p_strconcat(ctx->set_pool, prefix, key, NULL);
		new_link->full_key = full_key;
		new_link->parent = link;
		new_link->info = def->list_info;
		new_link->array = arr;
		new_link->change_array = carr;
		new_link->set_struct = new_set;
		new_link->change_struct = new_changes;
		i_assert(hash_table_lookup(ctx->links, full_key) == NULL);
		hash_table_insert(ctx->links, full_key, new_link);

		info.defaults = children[i];
		setting_parser_copy_defaults(ctx, &info, new_link);
	} T_END;
}

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
		case SET_DEFLIST_UNIQUE:
			copy_unique_defaults(ctx, def, link);
			break;
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

	parser_pool = pool_alloconly_create(MEMPOOL_GROWING"settings parser",
					    1024);
	ctx = p_new(parser_pool, struct setting_parser_context, 1);
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

	ctx->root_count = count;
	ctx->roots = p_new(ctx->parser_pool, struct setting_link, count);
	for (i = 0; i < count; i++) {
		ctx->roots[i].info = roots[i];
		if (roots[i]->struct_size == 0)
			continue;

		ctx->roots[i].set_struct =
			p_malloc(ctx->set_pool, roots[i]->struct_size);
		if ((flags & SETTINGS_PARSER_FLAG_TRACK_CHANGES) != 0) {
			ctx->roots[i].change_struct =
				p_malloc(ctx->set_pool, roots[i]->struct_size);
		}
		setting_parser_copy_defaults(ctx, roots[i], &ctx->roots[i]);
	}

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

void **settings_parser_get_list(const struct setting_parser_context *ctx)
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

const struct setting_parser_info *const *
settings_parser_get_roots(const struct setting_parser_context *ctx)
{
	const struct setting_parser_info **infos;
	unsigned int i;

	infos = t_new(const struct setting_parser_info *, ctx->root_count + 1);
	for (i = 0; i < ctx->root_count; i++)
		infos[i] = ctx->roots[i].info;
	return infos;
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
		ctx->error = p_strdup_printf(ctx->parser_pool,
			"Invalid boolean value: %s (use yes or no)", value);
		return -1;
	}

	return 0;
}

static int
get_uint(struct setting_parser_context *ctx, const char *value,
	 unsigned int *result_r)
{
	if (str_to_uint(value, result_r) < 0) {
		ctx->error = p_strdup_printf(ctx->parser_pool,
			"Invalid number %s: %s", value,
			str_num_error(value));
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
		ctx->error = p_strconcat(ctx->parser_pool, "Invalid number: ",
					 value, NULL);
		return -1;
	}
	*result_r = (unsigned int)octal;
	return 0;
}

static int settings_get_time_full(const char *str, unsigned int *interval_r,
				  bool milliseconds, const char **error_r)
{
	uintmax_t num, multiply = milliseconds ? 1000 : 1;
	const char *p;

	if (str_parse_uintmax(str, &num, &p) < 0) {
		*error_r = t_strconcat("Invalid time interval: ", str, NULL);
		return -1;
	}
	while (*p == ' ') p++;
	if (*p == '\0' && num != 0) {
		*error_r = t_strdup_printf("Time interval '%s' is missing units "
			"(add e.g. 's' for seconds)", str);
		return -1;
	}
	switch (i_toupper(*p)) {
	case 'S':
		multiply *= 1;
		if (strncasecmp(p, "secs", strlen(p)) == 0 ||
		    strncasecmp(p, "seconds", strlen(p)) == 0)
			p = "";
		break;
	case 'M':
		multiply *= 60;
		if (strncasecmp(p, "mins", strlen(p)) == 0 ||
		    strncasecmp(p, "minutes", strlen(p)) == 0)
			p = "";
		else if (strncasecmp(p, "msecs", strlen(p)) == 0 ||
			 strncasecmp(p, "mseconds", strlen(p)) == 0 ||
			 strncasecmp(p, "millisecs", strlen(p)) == 0 ||
			 strncasecmp(p, "milliseconds", strlen(p)) == 0) {
			if (milliseconds || (num % 1000) == 0) {
				if (!milliseconds) {
					/* allow ms also for seconds, as long
					   as it's divisible by seconds */
					num /= 1000;
				}
				multiply = 1;
				p = "";
				break;
			}
			*error_r = t_strdup_printf(
				"Milliseconds not supported for this setting: %s", str);
			return -1;
		}
		break;
	case 'H':
		multiply *= 60*60;
		if (strncasecmp(p, "hours", strlen(p)) == 0)
			p = "";
		break;
	case 'D':
		multiply *= 60*60*24;
		if (strncasecmp(p, "days", strlen(p)) == 0)
			p = "";
		break;
	case 'W':
		multiply *= 60*60*24*7;
		if (strncasecmp(p, "weeks", strlen(p)) == 0)
			p = "";
		break;
	}

	if (*p != '\0') {
		*error_r = t_strconcat("Invalid time interval: ", str, NULL);
		return -1;
	}
	if (num > UINT_MAX / multiply) {
		*error_r = t_strconcat("Time interval is too large: ",
				       str, NULL);
		return -1;
	}
	*interval_r = num * multiply;
	return 0;
}

int settings_get_time(const char *str, unsigned int *secs_r,
		      const char **error_r)
{
	return settings_get_time_full(str, secs_r, FALSE, error_r);
}

int settings_get_time_msecs(const char *str, unsigned int *msecs_r,
			    const char **error_r)
{
	return settings_get_time_full(str, msecs_r, TRUE, error_r);
}

int settings_get_size(const char *str, uoff_t *bytes_r,
		      const char **error_r)
{
	uintmax_t num, multiply = 1;
	const char *p;

	if (str_parse_uintmax(str, &num, &p) < 0) {
		*error_r = t_strconcat("Invalid size: ", str, NULL);
		return -1;
	}
	while (*p == ' ') p++;
	switch (i_toupper(*p)) {
	case 'B':
		multiply = 1;
		p += 1;
		break;
	case 'K':
		multiply = 1024;
		p += 1;
		break;
	case 'M':
		multiply = 1024*1024;
		p += 1;
		break;
	case 'G':
		multiply = 1024*1024*1024;
		p += 1;
		break;
	case 'T':
		multiply = 1024ULL*1024*1024*1024;
		p += 1;
		break;
	}

	if (multiply > 1) {
		/* Allow: k, ki, kiB */
		if (i_toupper(*p) == 'I')
			p++;
		if (i_toupper(*p) == 'B')
			p++;
	}
	if (*p != '\0') {
		*error_r = t_strconcat("Invalid size: ", str, NULL);
		return -1;
	}
	if (num > ((uoff_t)-1) / multiply) {
		*error_r = t_strconcat("Size is too large: ", str, NULL);
		return -1;
	}
	*bytes_r = num * multiply;
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

static void
setting_link_init_set_struct(struct setting_parser_context *ctx,
			     struct setting_link *link)
{
        void *ptr;

	link->set_struct = p_malloc(ctx->set_pool, link->info->struct_size);
	if ((ctx->flags & SETTINGS_PARSER_FLAG_TRACK_CHANGES) != 0) {
		link->change_struct =
			p_malloc(ctx->set_pool, link->info->struct_size);
		array_push_back(link->change_array, &link->change_struct);
	}

	setting_parser_copy_defaults(ctx, link->info, link);
	array_push_back(link->array, &link->set_struct);

	if (link->info->parent_offset != (size_t)-1 && link->parent != NULL) {
		ptr = STRUCT_MEMBER_P(link->set_struct,
				      link->info->parent_offset);
		*((void **)ptr) = link->parent->set_struct;
	}
}

static int ATTR_NULL(2)
setting_link_add(struct setting_parser_context *ctx,
		 const struct setting_define *def,
		 const struct setting_link *link_copy, char *key)
{
	struct setting_link *link;

	link = hash_table_lookup(ctx->links, key);
	if (link != NULL) {
		if (link->parent == link_copy->parent &&
		    link->info == link_copy->info &&
		    (def == NULL || def->type == SET_DEFLIST_UNIQUE))
			return 0;
		ctx->error = p_strconcat(ctx->parser_pool, key,
					 " already exists", NULL);
		return -1;
	}

	link = p_new(ctx->parser_pool, struct setting_link, 1);
	*link = *link_copy;
	link->full_key = key;
	i_assert(hash_table_lookup(ctx->links, key) == NULL);
	hash_table_insert(ctx->links, key, link);

	if (link->info->struct_size != 0)
		setting_link_init_set_struct(ctx, link);
	return 0;
}

static int ATTR_NULL(3, 8)
get_deflist(struct setting_parser_context *ctx, struct setting_link *parent,
	    const struct setting_define *def,
	    const struct setting_parser_info *info,
	    const char *key, const char *value, ARRAY_TYPE(void_array) *result,
	    ARRAY_TYPE(void_array) *change_result)
{
	struct setting_link new_link;
	const char *const *list;
	char *full_key;

	i_assert(info->defines != NULL || info == &strlist_info);

	if (!array_is_created(result))
		p_array_init(result, ctx->set_pool, 5);
	if (change_result != NULL && !array_is_created(change_result))
		p_array_init(change_result, ctx->set_pool, 5);

	i_zero(&new_link);
	new_link.parent = parent;
	new_link.info = info;
	new_link.array = result;
	new_link.change_array = change_result;

	if (info == &strlist_info) {
		/* there are no sections below strlist, so allow referencing it
		   without the key (e.g. plugin/foo instead of plugin/0/foo) */
		full_key = p_strdup(ctx->parser_pool, key);
		if (setting_link_add(ctx, def, &new_link, full_key) < 0)
			return -1;
	}

	list = t_strsplit(value, ",\t ");
	for (; *list != NULL; list++) {
		if (**list == '\0')
			continue;

		full_key = p_strconcat(ctx->parser_pool, key,
				       SETTINGS_SEPARATOR_S, *list, NULL);
		if (setting_link_add(ctx, def, &new_link, full_key) < 0)
			return -1;
	}
	return 0;
}

static int
get_in_port_zero(struct setting_parser_context *ctx, const char *value,
	 in_port_t *result_r)
{
	if (net_str2port_zero(value, result_r) < 0) {
		ctx->error = p_strdup_printf(ctx->parser_pool,
			"Invalid port number %s", value);
		return -1;
	}
	return 0;
}

static int
settings_parse(struct setting_parser_context *ctx, struct setting_link *link,
	       const struct setting_define *def,
	       const char *key, const char *value)
{
	void *ptr, *change_ptr;
	const void *ptr2;
	const char *error;

	while (def->type == SET_ALIAS) {
		i_assert(def != link->info->defines);
		def--;
	}

	ctx->prev_info = link->info;

	if (link->set_struct == NULL)
		setting_link_init_set_struct(ctx, link);

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
		if (settings_get_time(value, (unsigned int *)ptr, &error) < 0) {
			ctx->error = p_strdup(ctx->parser_pool, error);
			return -1;
		}
		break;
	case SET_TIME_MSECS:
		if (settings_get_time_msecs(value, (unsigned int *)ptr, &error) < 0) {
			ctx->error = p_strdup(ctx->parser_pool, error);
			return -1;
		}
		break;
	case SET_SIZE:
		if (settings_get_size(value, (uoff_t *)ptr, &error) < 0) {
			ctx->error = p_strdup(ctx->parser_pool, error);
			return -1;
		}
		break;
	case SET_IN_PORT:
		if (get_in_port_zero(ctx, value, (in_port_t *)ptr) < 0)
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
		ptr2 = CONST_STRUCT_MEMBER_P(link->info->defaults, def->offset);
		if (get_enum(ctx, value, (char **)ptr,
			     *(const char *const *)ptr2) < 0)
			return -1;
		break;
	case SET_DEFLIST:
	case SET_DEFLIST_UNIQUE:
		ctx->prev_info = def->list_info;
		return get_deflist(ctx, link, def, def->list_info,
				   key, value, (ARRAY_TYPE(void_array) *)ptr,
				   (ARRAY_TYPE(void_array) *)change_ptr);
	case SET_STRLIST: {
		ctx->prev_info = &strlist_info;
		if (get_deflist(ctx, link, NULL, &strlist_info, key, value,
				(ARRAY_TYPE(void_array) *)ptr, NULL) < 0)
			return -1;
		break;
	}
	case SET_ALIAS:
		i_unreached();
		break;
	}

	if (change_ptr != NULL)
		*((char *)change_ptr) = 1;
	return 0;
}

static bool
settings_find_key_nth(struct setting_parser_context *ctx, const char *key,
		      unsigned int *n, const struct setting_define **def_r,
		      struct setting_link **link_r)
{
	const struct setting_define *def;
	struct setting_link *link;
	const char *end, *parent_key;
	unsigned int i;

	/* try to find from roots */
	for (i = *n; i < ctx->root_count; i++) {
		def = setting_define_find(ctx->roots[i].info, key);
		if (def != NULL) {
			*n = i + 1;
			*def_r = def;
			*link_r = &ctx->roots[i];
			return TRUE;
		}
	}
	if (*n > ctx->root_count)
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

		if (!settings_find_key_nth(ctx, parent_key, &parent_n,
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
	if (link->info == &strlist_info) {
		*def_r = NULL;
		return TRUE;
	} else {
		*def_r = setting_define_find(link->info, end + 1);
		return *def_r != NULL;
	}
}

static bool
settings_find_key(struct setting_parser_context *ctx, const char *key,
		  const struct setting_define **def_r,
		  struct setting_link **link_r)
{
	unsigned int n = 0;

	return settings_find_key_nth(ctx, key, &n, def_r, link_r);
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

int settings_parse_keyvalue(struct setting_parser_context *ctx,
			    const char *key, const char *value)
{
	const struct setting_define *def;
	struct setting_link *link;
	unsigned int n = 0;

	ctx->error = NULL;
	ctx->prev_info = NULL;

	if (!settings_find_key_nth(ctx, key, &n, &def, &link)) {
		ctx->error = p_strconcat(ctx->parser_pool,
					 "Unknown setting: ", key, NULL);
		return 0;
	}

	do {
		if (def == NULL) {
			i_assert(link->info == &strlist_info);
			settings_parse_strlist(ctx, link, key, value);
			return 1;
		}

		if (settings_parse(ctx, link, def, key, value) < 0)
			return -1;
		/* there may be more instances of the setting */
	} while (settings_find_key_nth(ctx, key, &n, &def, &link));
	return 1;
}

bool settings_parse_is_valid_key(struct setting_parser_context *ctx,
				 const char *key)
{
	const struct setting_define *def;
	struct setting_link *link;

	return settings_find_key(ctx, key, &def, &link);
}

const char *settings_parse_unalias(struct setting_parser_context *ctx,
				   const char *key)
{
	const struct setting_define *def;
	struct setting_link *link;

	if (!settings_find_key(ctx, key, &def, &link))
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

	if (!settings_find_key(ctx, key, &def, &link))
		return NULL;
	if (link->set_struct == NULL || def == NULL)
		return NULL;

	*type_r = def->type;
	return STRUCT_MEMBER_P(link->set_struct, def->offset);
}

bool settings_parse_is_changed(struct setting_parser_context *ctx,
			       const char *key)
{
	const struct setting_define *def;
	struct setting_link *link;
	const unsigned char *p;

	if (!settings_find_key(ctx, key, &def, &link))
		return FALSE;
	if (link->change_struct == NULL || def == NULL)
		return FALSE;

	p = STRUCT_MEMBER_P(link->change_struct, def->offset);
	return *p != 0;
}

int settings_parse_line(struct setting_parser_context *ctx, const char *line)
{
	const char *key, *value;
	int ret;

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
		if (ctx->linenum == 1 && str_begins(line, "ERROR ")) {
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

	do {
		if ((ret = settings_parse_stream(ctx, input)) < 0)
			return -1;
		if (ret == 0) {
			/* empty line read */
			return 0;
		}
	} while ((ret = i_stream_read(input)) > 0);

	switch (ret) {
	case -1:
		if (ctx->error != NULL)
			break;
		if (input->stream_errno != 0) {
			ctx->error = p_strdup_printf(ctx->parser_pool,
				"read(%s) failed: %s", i_stream_get_name(input),
				i_stream_get_error(input));
		} else if (input->v_offset == 0) {
			ctx->error = p_strdup_printf(ctx->parser_pool,
				"read(%s) disconnected before receiving any data",
				i_stream_get_name(input));
		} else {
			ctx->error = p_strdup_printf(ctx->parser_pool,
				"read(%s) disconnected before receiving "
				"end-of-settings line",
				i_stream_get_name(input));
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

	input = i_stream_create_fd_autoclose(&fd, max_line_length);
	i_stream_set_name(input, path);
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
	char **environ = *env_get_environ_p();
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
		array_push_back(&sorted_envs_arr, &environ[i]);
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
		i_close_fd(&fd[0]);
		i_close_fd(&fd[1]);
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
		i_close_fd(&fd[0]);
		if (dup2(fd[1], STDOUT_FILENO) < 0)
			i_fatal("dup2() failed: %m");

		execv_const(argv[0], argv);
	}
	i_close_fd(&fd[1]);

	input = i_stream_create_fd_autoclose(&fd[0], (size_t)-1);
	i_stream_set_name(input, bin_path);
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
settings_check_dynamic(const struct setting_parser_info *info, pool_t pool,
		       void *set, const char **error_r)
{
	unsigned int i;

	if (info->dynamic_parsers == NULL)
		return TRUE;

	for (i = 0; info->dynamic_parsers[i].name != NULL; i++) {
		struct dynamic_settings_parser *dyn = &info->dynamic_parsers[i];

		if (!settings_check(dyn->info, pool,
				    PTR_OFFSET(set, dyn->struct_offset),
				    error_r))
			return FALSE;
	}
	return TRUE;
}

bool settings_check(const struct setting_parser_info *info, pool_t pool,
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
		if (!SETTING_TYPE_IS_DEFLIST(def->type))
			continue;

		val = CONST_PTR_OFFSET(set, def->offset);
		if (!array_is_created(val))
			continue;

		children = array_get(val, &count);
		for (i = 0; i < count; i++) {
			if (!settings_check(def->list_info, pool,
					    children[i], error_r))
				return FALSE;
		}
	}
	return settings_check_dynamic(info, pool, set, error_r);
}

bool settings_parser_check(struct setting_parser_context *ctx, pool_t pool,
			   const char **error_r)
{
	unsigned int i;

	for (i = 0; i < ctx->root_count; i++) {
		if (!settings_check(ctx->roots[i].info, pool,
				    ctx->roots[i].set_struct, error_r))
			return FALSE;
	}
	return TRUE;
}

void settings_parse_set_expanded(struct setting_parser_context *ctx,
				 bool is_expanded)
{
	ctx->str_vars_are_expanded = is_expanded;
}

void settings_parse_set_key_expanded(struct setting_parser_context *ctx,
				     pool_t pool, const char *key)
{
	const struct setting_define *def;
	struct setting_link *link;
	const char **val;

	if (!settings_find_key(ctx, key, &def, &link))
		return;
	if (def == NULL) {
		/* parent is strlist, no expansion needed */
		i_assert(link->info == &strlist_info);
		return;
	}

	val = PTR_OFFSET(link->set_struct, def->offset);
	if (def->type == SET_STR_VARS && *val != NULL) {
		i_assert(**val == SETTING_STRVAR_UNEXPANDED[0] ||
			 **val == SETTING_STRVAR_EXPANDED[0]);
		*val = p_strconcat(pool, SETTING_STRVAR_EXPANDED,
				   *val + 1, NULL);
	}
}

void settings_parse_set_keys_expanded(struct setting_parser_context *ctx,
				      pool_t pool, const char *const *keys)
{
	for (; *keys != NULL; keys++)
		settings_parse_set_key_expanded(ctx, pool, *keys);
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
	void *value, *const *children;
	const char *error;
	unsigned int i, count;
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
		case SET_DEFLIST:
		case SET_DEFLIST_UNIQUE: {
			const ARRAY_TYPE(void_array) *val = value;

			if (!array_is_created(val))
				break;

			children = array_get(val, &count);
			for (i = 0; i < count; i++) {
				ret = settings_var_expand_info(def->list_info,
					children[i], pool, table, func_table,
					func_context, str, &error);
				if (final_ret > ret) {
					final_ret = ret;
					*error_r = error;
				}
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
	if (info->dynamic_parsers != NULL) {
		for (i = 0; info->dynamic_parsers[i].name != NULL; i++) {
			struct dynamic_settings_parser *dyn = &info->dynamic_parsers[i];
			const struct setting_parser_info *dinfo = dyn->info;
			void *dset = PTR_OFFSET(set, dyn->struct_offset);

			if (dinfo->expand_check_func != NULL) {
				if (!dinfo->expand_check_func(dset, pool, error_r))
					return -1;
			}
		}
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
	char *error_dup = NULL;
	int ret;

	T_BEGIN {
		const char *error;
		string_t *str = t_str_new(256);

		ret = settings_var_expand_info(info, set, pool, table,
					       func_table, func_context, str,
					       &error);
		if (ret <= 0)
			error_dup = i_strdup(error);
	} T_END;
	*error_r = t_strdup(error_dup);
	i_free(error_dup);
	return ret;
}

void settings_parse_var_skip(struct setting_parser_context *ctx)
{
	unsigned int i;
	const char *error;

	for (i = 0; i < ctx->root_count; i++) {
		(void)settings_var_expand_info(ctx->roots[i].info,
					       ctx->roots[i].set_struct,
					       NULL, NULL, NULL, NULL, NULL,
					       &error);
	}
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
		case SET_ALIAS:
			break;
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
		case SET_DEFLIST:
		case SET_DEFLIST_UNIQUE: {
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
	case SET_DEFLIST:
	case SET_DEFLIST_UNIQUE:
		return FALSE;
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
	case SET_ALIAS:
		break;
	}
	return TRUE;
}

static void *settings_dup_full(const struct setting_parser_info *info,
			       const void *set, pool_t pool, bool keep_values)
{
	const struct setting_define *def;
	const void *src;
	void *dest_set, *dest, *const *children;
	unsigned int i, count;

	if (info->struct_size == 0)
		return NULL;

	/* don't just copy everything from set to dest_set. it may contain
	   some non-setting fields allocated from the original pool. */
	dest_set = p_malloc(pool, info->struct_size);
	for (def = info->defines; def->key != NULL; def++) {
		src = CONST_PTR_OFFSET(set, def->offset);
		dest = PTR_OFFSET(dest_set, def->offset);

		if (!setting_copy(def->type, src, dest, pool, keep_values)) {
			const ARRAY_TYPE(void_array) *src_arr = src;
			ARRAY_TYPE(void_array) *dest_arr = dest;
			void *child_set;

			if (!array_is_created(src_arr))
				continue;

			children = array_get(src_arr, &count);
			p_array_init(dest_arr, pool, count);
			for (i = 0; i < count; i++) {
				child_set = settings_dup_full(def->list_info,
							      children[i], pool,
							      keep_values);
				array_push_back(dest_arr, &child_set);
				settings_set_parent(def->list_info, child_set,
						    dest_set);
			}
		}
	}
	return dest_set;
}

void *settings_dup(const struct setting_parser_info *info,
		   const void *set, pool_t pool)
{
	return settings_dup_full(info, set, pool, FALSE);
}

void *settings_dup_with_pointers(const struct setting_parser_info *info,
				 const void *set, pool_t pool)
{
	return settings_dup_full(info, set, pool, TRUE);
}

static void *
settings_changes_dup(const struct setting_parser_info *info,
		     const void *change_set, pool_t pool)
{
	const struct setting_define *def;
	const void *src;
	void *dest_set, *dest, *const *children;
	unsigned int i, count;

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
			*((char *)dest) = *((const char *)src);
			break;
		case SET_DEFLIST:
		case SET_DEFLIST_UNIQUE: {
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
				array_push_back(dest_arr, &child_set);
			}
			break;
		}
		case SET_ALIAS:
			break;
		}
	}
	return dest_set;
}

static void
info_update_real(pool_t pool, struct setting_parser_info *parent,
		 const struct dynamic_settings_parser *parsers)
{
	/* @UNSAFE */
	ARRAY(struct setting_define) defines;
	ARRAY_TYPE(dynamic_settings_parser) dynamic_parsers;
	struct dynamic_settings_parser new_parser;
	const struct setting_define *cur_defines;
	struct setting_define *new_defines, new_define;
	void *parent_defaults;
	unsigned int i, j;
	size_t offset, new_struct_size;

	t_array_init(&defines, 128);
	/* add existing defines */
	for (j = 0; parent->defines[j].key != NULL; j++)
		array_push_back(&defines, &parent->defines[j]);
	new_struct_size = MEM_ALIGN(parent->struct_size);

	/* add new dynamic defines */
	for (i = 0; parsers[i].name != NULL; i++) {
		i_assert(parsers[i].info->parent == parent);
		cur_defines = parsers[i].info->defines;
		for (j = 0; cur_defines[j].key != NULL; j++) {
			new_define = cur_defines[j];
			new_define.offset += new_struct_size;
			array_push_back(&defines, &new_define);
		}
		new_struct_size += MEM_ALIGN(parsers[i].info->struct_size);
	}
	new_defines = p_new(pool, struct setting_define,
			    array_count(&defines) + 1);
	memcpy(new_defines, array_front(&defines),
	       sizeof(*parent->defines) * array_count(&defines));
	parent->defines = new_defines;

	/* update defaults */
	parent_defaults = p_malloc(pool, new_struct_size);
	memcpy(parent_defaults, parent->defaults, parent->struct_size);
	offset = MEM_ALIGN(parent->struct_size);
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
			array_push_back(&dynamic_parsers,
					&parent->dynamic_parsers[i]);
		}
	}
	offset = MEM_ALIGN(parent->struct_size);
	for (i = 0; parsers[i].name != NULL; i++) {
		new_parser = parsers[i];
		new_parser.name = p_strdup(pool, new_parser.name);
		new_parser.struct_offset = offset;
		array_push_back(&dynamic_parsers, &new_parser);
		offset += MEM_ALIGN(parsers[i].info->struct_size);
	}
	parent->dynamic_parsers =
		p_new(pool, struct dynamic_settings_parser,
		      array_count(&dynamic_parsers) + 1);
	memcpy(parent->dynamic_parsers, array_front(&dynamic_parsers),
	       sizeof(*parent->dynamic_parsers) *
	       array_count(&dynamic_parsers));
	parent->struct_size = new_struct_size;
}

void settings_parser_info_update(pool_t pool,
				 struct setting_parser_info *parent,
				 const struct dynamic_settings_parser *parsers)
{
	if (parsers[0].name != NULL) T_BEGIN {
		info_update_real(pool, parent, parsers);
	} T_END;
}

static void
settings_parser_update_children_parent(struct setting_parser_info *parent,
				       pool_t pool)
{
	struct setting_define *new_defs;
	struct setting_parser_info *new_info;
	unsigned int i, count;

	for (count = 0; parent->defines[count].key != NULL; count++) ;

	new_defs = p_new(pool, struct setting_define, count + 1);
	memcpy(new_defs, parent->defines, sizeof(*new_defs) * count);
	parent->defines = new_defs;

	for (i = 0; i < count; i++) {
		if (new_defs[i].list_info == NULL ||
		    new_defs[i].list_info->parent == NULL)
			continue;

		new_info = p_new(pool, struct setting_parser_info, 1);
		*new_info = *new_defs[i].list_info;
		new_info->parent = parent;
		new_defs[i].list_info = new_info;
	}
}

void settings_parser_dyn_update(pool_t pool,
				const struct setting_parser_info *const **_roots,
				const struct dynamic_settings_parser *dyn_parsers)
{
	const struct setting_parser_info *const *roots = *_roots;
	const struct setting_parser_info *old_parent, **new_roots;
	struct setting_parser_info *new_parent, *new_info;
	struct dynamic_settings_parser *new_dyn_parsers;
	unsigned int i, count;

	/* settings_parser_info_update() modifies the parent structure.
	   since we may be using the same structure later, we want it to be
	   in its original state, so we'll have to copy all structures. */
	old_parent = dyn_parsers[0].info->parent;
	new_parent = p_new(pool, struct setting_parser_info, 1);
	*new_parent = *old_parent;
	settings_parser_update_children_parent(new_parent, pool);

	/* update root */
	for (count = 0; roots[count] != NULL; count++) ;
	new_roots = p_new(pool, const struct setting_parser_info *, count + 1);
	for (i = 0; i < count; i++) {
		if (roots[i] == old_parent)
			new_roots[i] = new_parent;
		else
			new_roots[i] = roots[i];
	}
	*_roots = new_roots;

	/* update parent in dyn_parsers */
	for (count = 0; dyn_parsers[count].name != NULL; count++) ;
	new_dyn_parsers = p_new(pool, struct dynamic_settings_parser, count + 1);
	for (i = 0; i < count; i++) {
		new_dyn_parsers[i] = dyn_parsers[i];

		new_info = p_new(pool, struct setting_parser_info, 1);
		*new_info = *dyn_parsers[i].info;
		new_info->parent = new_parent;
		new_dyn_parsers[i].info = new_info;
	}

	settings_parser_info_update(pool, new_parent, new_dyn_parsers);
}

const void *settings_find_dynamic(const struct setting_parser_info *info,
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
	unsigned int i;
	pool_t parser_pool;
	bool keep_values;

	/* if source and destination pools are the same, there's no need to
	   duplicate values */
	keep_values = new_pool == old_ctx->set_pool;

	pool_ref(new_pool);
	parser_pool = pool_alloconly_create(MEMPOOL_GROWING"dup settings parser",
					    1024);
	new_ctx = p_new(parser_pool, struct setting_parser_context, 1);
	new_ctx->set_pool = new_pool;
	new_ctx->parser_pool = parser_pool;
	new_ctx->flags = old_ctx->flags;
	new_ctx->str_vars_are_expanded = old_ctx->str_vars_are_expanded;
	new_ctx->linenum = old_ctx->linenum;
	new_ctx->error = p_strdup(new_ctx->parser_pool, old_ctx->error);
	new_ctx->prev_info = old_ctx->prev_info;

	hash_table_create_direct(&links, new_ctx->parser_pool, 0);

	new_ctx->root_count = old_ctx->root_count;
	new_ctx->roots = p_new(new_ctx->parser_pool, struct setting_link,
			       new_ctx->root_count);
	for (i = 0; i < new_ctx->root_count; i++) {
		i_assert(old_ctx->roots[i].parent == NULL);
		i_assert(old_ctx->roots[i].array == NULL);

		new_ctx->roots[i].info = old_ctx->roots[i].info;
		new_ctx->roots[i].set_struct =
			settings_dup_full(old_ctx->roots[i].info,
					  old_ctx->roots[i].set_struct,
					  new_ctx->set_pool, keep_values);
		new_ctx->roots[i].change_struct =
			settings_changes_dup(old_ctx->roots[i].info,
					     old_ctx->roots[i].change_struct,
					     new_ctx->set_pool);
		hash_table_insert(links, &old_ctx->roots[i],
				  &new_ctx->roots[i]);
	}

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

static void *
settings_changes_init(const struct setting_parser_info *info,
		      const void *change_set, pool_t pool)
{
	const struct setting_define *def;
	const ARRAY_TYPE(void_array) *src_arr;
	ARRAY_TYPE(void_array) *dest_arr;
	void *dest_set, *set, *const *children;
	unsigned int i, count;

	if (info->struct_size == 0)
		return NULL;

	dest_set = p_malloc(pool, info->struct_size);
	for (def = info->defines; def->key != NULL; def++) {
		if (!SETTING_TYPE_IS_DEFLIST(def->type))
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
				array_push_back(dest_arr, &set);
			}
		}
	}
	return dest_set;
}

static void settings_copy_deflist(const struct setting_define *def,
				  const struct setting_link *src_link,
				  struct setting_link *dest_link,
				  pool_t pool)
{
	const ARRAY_TYPE(void_array) *src_arr;
	ARRAY_TYPE(void_array) *dest_arr;
	void *const *children, *child_set;
	unsigned int i, count;

	src_arr = CONST_PTR_OFFSET(src_link->set_struct, def->offset);
	dest_arr = PTR_OFFSET(dest_link->set_struct, def->offset);

	if (!array_is_created(src_arr))
		return;

	children = array_get(src_arr, &count);
	if (!array_is_created(dest_arr))
		p_array_init(dest_arr, pool, count);
	for (i = 0; i < count; i++) {
		child_set = settings_dup(def->list_info, children[i], pool);
		array_push_back(dest_arr, &child_set);
		settings_set_parent(def->list_info, child_set,
				    dest_link->set_struct);
	}

	/* copy changes */
	dest_arr = PTR_OFFSET(dest_link->change_struct, def->offset);
	if (!array_is_created(dest_arr))
		p_array_init(dest_arr, pool, count);
	for (i = 0; i < count; i++) {
		child_set = settings_changes_init(def->list_info,
						  children[i], pool);
		array_push_back(dest_arr, &child_set);
	}
}

static int
settings_copy_deflist_unique(const struct setting_define *def,
			     const struct setting_link *src_link,
			     struct setting_link *dest_link,
			     pool_t pool, const char **conflict_key_r)
{
	struct setting_link child_dest_link, child_src_link;
	const ARRAY_TYPE(void_array) *src_arr, *src_carr;
	ARRAY_TYPE(void_array) *dest_arr, *dest_carr;
	void *const *src_children, *const *src_cchildren;
	void *const *dest_children, *const *dest_cchildren, *child_set;
	const char *const *src_namep, *const *dest_namep;
	unsigned int i, j, src_count, dest_count, ccount;
	unsigned int type_offset;

	i_assert(def->list_info->type_offset != (size_t)-1);

	src_arr = CONST_PTR_OFFSET(src_link->set_struct, def->offset);
	src_carr = CONST_PTR_OFFSET(src_link->change_struct, def->offset);
	dest_arr = PTR_OFFSET(dest_link->set_struct, def->offset);
	dest_carr = PTR_OFFSET(dest_link->change_struct, def->offset);

	if (!array_is_created(src_arr))
		return 0;
	type_offset = def->list_info->type_offset;

	i_zero(&child_dest_link);
	i_zero(&child_src_link);

	child_dest_link.info = child_src_link.info = def->list_info;

	src_children = array_get(src_arr, &src_count);
	src_cchildren = array_get(src_carr, &ccount);
	i_assert(src_count == ccount);
	if (!array_is_created(dest_arr)) {
		p_array_init(dest_arr, pool, src_count);
		p_array_init(dest_carr, pool, src_count);
	}
	for (i = 0; i < src_count; i++) {
		src_namep = CONST_PTR_OFFSET(src_children[i], type_offset);
		dest_children = array_get(dest_arr, &dest_count);
		dest_cchildren = array_get(dest_carr, &ccount);
		i_assert(dest_count == ccount);
		for (j = 0; j < dest_count; j++) {
			dest_namep = CONST_PTR_OFFSET(dest_children[j],
						      type_offset);
			if (strcmp(*src_namep, *dest_namep) == 0)
				break;
		}

		if (j < dest_count && **src_namep != '\0') {
			/* merge */
			child_src_link.set_struct = src_children[i];
			child_src_link.change_struct = src_cchildren[i];
			child_dest_link.set_struct = dest_children[j];
			child_dest_link.change_struct = dest_cchildren[j];
			if (settings_apply(&child_dest_link, &child_src_link,
					   pool, conflict_key_r) < 0)
				return -1;
		} else {
			/* append */
			child_set = settings_dup(def->list_info,
						 src_children[i], pool);
			array_push_back(dest_arr, &child_set);
			settings_set_parent(def->list_info, child_set,
					    dest_link->set_struct);

			child_set = settings_changes_init(def->list_info,
							  src_cchildren[i],
							  pool);
			array_push_back(dest_carr, &child_set);
		}
	}
	return 0;
}

static int
settings_apply(struct setting_link *dest_link,
	       const struct setting_link *src_link,
	       pool_t pool, const char **conflict_key_r)
{
	const struct setting_define *def;
	const void *src, *csrc;
	void *dest, *cdest;

	for (def = dest_link->info->defines; def->key != NULL; def++) {
		csrc = CONST_PTR_OFFSET(src_link->change_struct, def->offset);
		cdest = PTR_OFFSET(dest_link->change_struct, def->offset);

		if (def->type == SET_DEFLIST || def->type == SET_STRLIST) {
			/* just add the new values */
		} else if (def->type == SET_DEFLIST_UNIQUE) {
			/* merge sections */
		} else if (*((const char *)csrc) == 0) {
			/* unchanged */
			continue;
		} else if (def->type == SET_ALIAS) {
			/* ignore aliases */
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

		if (setting_copy(def->type, src, dest, pool, FALSE)) {
			/* non-list */
		} else if (def->type == SET_DEFLIST) {
			settings_copy_deflist(def, src_link, dest_link, pool);
		} else {
			i_assert(def->type == SET_DEFLIST_UNIQUE);
			if (settings_copy_deflist_unique(def, src_link,
							 dest_link, pool,
							 conflict_key_r) < 0)
				return -1;
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
	if (name[i] == '\0')
		return name;

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

