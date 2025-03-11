/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "crc32.h"
#include "str.h"
#include "str-parse.h"
#include "read-full.h"
#include "var-expand.h"
#include "settings-parser.h"

#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

struct boollist_removal {
	ARRAY_TYPE(const_string) *array;
	const char *key_suffix;
};

struct setting_parser_context {
	pool_t set_pool, parser_pool;
	int refcount;
        enum settings_parser_flags flags;

	const struct setting_parser_info *info;

	/* Pointer to structure containing the values */
	void *set_struct;
	ARRAY(struct boollist_removal) boollist_removals;

	char *error;
};

const char *set_value_unknown = "UNKNOWN_VALUE_WITH_VARIABLES";

#ifdef DEBUG
static const char *boollist_eol_sentry = "boollist-eol";
#endif
static const char *set_array_stop = "array-stop";

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
			strp = PTR_OFFSET(ctx->set_struct, def->offset);
			p = strchr(*strp, ':');
			if (p != NULL)
				*strp = p_strdup_until(ctx->set_pool, *strp, p);
			break;
		}
		default:
			break;
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
		setting_parser_copy_defaults(ctx, root);
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

unsigned int
setting_parser_info_get_define_count(const struct setting_parser_info *info)
{
	unsigned int count = 0;
	while (info->defines[count].key != NULL)
		count++;
	return count;
}

bool setting_parser_info_find_key(const struct setting_parser_info *info,
				  const char *key, unsigned int *idx_r)
{
	const char *suffix;

	for (unsigned int i = 0; info->defines[i].key != NULL; i++) {
		if (!str_begins(key, info->defines[i].key, &suffix))
			; /* mismatch */
		else if (suffix[0] == '\0') {
			/* full setting */
			while (i > 0 && info->defines[i].type == SET_ALIAS)
				i--;
			*idx_r = i;
			return TRUE;
		} else if (suffix[0] == '/' &&
			   (info->defines[i].type == SET_STRLIST ||
			    info->defines[i].type == SET_BOOLLIST)) {
			/* strlist key */
			*idx_r = i;
			return TRUE;
		}
	}
	return FALSE;
}

void *settings_parser_get_set(const struct setting_parser_context *ctx)
{
	return ctx->set_struct;
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
get_uintmax(struct setting_parser_context *ctx, const char *value,
	    uintmax_t *result_r)
{
	if (str_to_uintmax(value, result_r) < 0) {
		settings_parser_set_error(ctx, t_strdup_printf(
			"Invalid number %s: %s", value,
			str_num_error(value)));
		return -1;
	}
	return 0;
}

static int
get_uint(struct setting_parser_context *ctx, const char *value,
	 unsigned int *result_r)
{
	if (settings_value_is_unlimited(value)) {
		*result_r = SET_UINT_UNLIMITED;
		return 0;
	}
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
get_file(struct setting_parser_context *ctx, bool dup_value, const char **value)
{
	if (**value == '\0')
		return 0;
	const char *content = strchr(*value, '\n');
	if (content != NULL) {
		if (dup_value)
			*value = p_strdup(ctx->set_pool, *value);
		return 0;
	}

	const char *error;
	if (settings_parse_read_file(*value, *value, ctx->set_pool, NULL,
				     value, &error) < 0) {
		settings_parser_set_error(ctx, error);
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

int settings_parse_read_file(const char *path, const char *value_path,
			     pool_t pool, struct stat *st_r,
			     const char **output_r, const char **error_r)
{
	struct stat st;
	int fd;

	if ((fd = open(path, O_RDONLY)) == -1) {
		*error_r = t_strdup_printf("open(%s) failed: %m", path);
		return -1;
	}
	if (fstat(fd, &st) < 0) {
		*error_r = t_strdup_printf("fstat(%s) failed: %m", path);
		i_close_fd(&fd);
		return -1;
	}
	size_t value_path_len = strlen(value_path);
	char *buf = p_malloc(pool, value_path_len + 1 + st.st_size + 1);
	memcpy(buf, value_path, value_path_len);
	buf[value_path_len] = '\n';

	int ret = read_full(fd, buf + value_path_len + 1, st.st_size);
	i_close_fd(&fd);
	if (ret < 0) {
		*error_r = t_strdup_printf("read(%s) failed: %m", path);
		return -1;
	}
	if (ret == 0) {
		*error_r = t_strdup_printf(
			"read(%s) failed: Unexpected EOF", path);
		return -1;
	}
	if (memchr(buf + value_path_len + 1, '\0', st.st_size) != NULL) {
		*error_r = t_strdup_printf(
			"%s contains NUL characters - This is not supported",
			path);
		return -1;
	}

	if (st_r != NULL)
		*st_r = st;
	*output_r = buf;
	return 0;
}

static int
settings_parse_strlist(struct setting_parser_context *ctx,
		       ARRAY_TYPE(const_string) *array,
		       const char *key, const char *value, const char **error_r)
{
	const char *const *items;
	const char *vkey, *vvalue;
	unsigned int i, count;

	/* If the next element after the visible array is set_array_stop, then
	   the strlist should not be modified any further. */
	if (array_is_created(array)) {
		items = array_get(array, &count);
		if (items[count] == set_array_stop)
			return 0;
	}

	const char *suffix = strchr(key, SETTINGS_SEPARATOR);
	if (suffix == NULL) {
		if (value[0] == '\0') {
			/* clear out the whole strlist */
			if (array_is_created(array))
				array_clear(array);
			return 0;
		}

		*error_r = t_strdup_printf(
			"Setting is a string list, use %s/key=value'", key);
		return -1;
	}
	key = settings_section_unescape(suffix + 1);
	vvalue = p_strdup(ctx->set_pool, value);

	if (!array_is_created(array))
		p_array_init(array, ctx->set_pool, 4);

	/* replace if it already exists */
	items = array_get(array, &count);
	for (i = 0; i < count; i += 2) {
		if (strcmp(items[i], key) == 0) {
			array_idx_set(array, i + 1, &vvalue);
			return 0;
		}
	}

	vkey = p_strdup(ctx->set_pool, key);
	array_push_back(array, &vkey);
	array_push_back(array, &vvalue);
	return 0;
}

int settings_parse_boollist_string(const char *value, pool_t pool,
				   ARRAY_TYPE(const_string) *dest,
				   const char **error_r)
{
	string_t *elem = t_str_new(32);
	const char *elem_dup;
	bool quoted = FALSE, end_of_quote = FALSE;
	for (unsigned int i = 0; value[i] != '\0'; i++) {
		switch (value[i]) {
		case '"':
			if (!quoted) {
				/* beginning of a string */
				if (str_len(elem) != 0) {
					*error_r = "'\"' in the middle of a string";
					return -1;
				}
				quoted = TRUE;
			} else if (end_of_quote) {
				*error_r = "Expected ',' or ' ' after '\"'";
				return -1;
			} else {
				/* end of a string */
				end_of_quote = TRUE;
			}
			break;
		case ' ':
		case ',':
			if (quoted && !end_of_quote) {
				/* inside a "quoted string" */
				str_append_c(elem, value[i]);
				break;
			}

			if (quoted || str_len(elem) > 0) {
				elem_dup = p_strdup(pool,
					settings_section_unescape(str_c(elem)));
				array_push_back(dest, &elem_dup);
				str_truncate(elem, 0);
			}
			quoted = FALSE;
			end_of_quote = FALSE;
			break;
		case '\\':
			if (quoted) {
				i++;
				if (value[i] == '\0') {
					*error_r = "Value ends with '\\'";
					return -1;
				}
			}
			/* fall through */
		default:
			if (end_of_quote) {
				*error_r = "Expected ',' or ' ' after '\"'";
				return -1;
			}
			str_append_c(elem, value[i]);
			break;
		}
	}
	if (quoted && !end_of_quote) {
		*error_r = "Missing ending '\"'";
		return -1;
	}
	if (quoted || str_len(elem) > 0) {
		elem_dup = p_strdup(pool, settings_section_unescape(str_c(elem)));
		array_push_back(dest, &elem_dup);
	}
	return 0;
}

const char *const *settings_boollist_get(const ARRAY_TYPE(const_string) *array)
{
	const char *const *strings = empty_str_array;
	unsigned int count;

	if (array_not_empty(array)) {
		strings = array_get(array, &count);
		i_assert(strings[count] == NULL);
#ifdef DEBUG
	i_assert(strings[count+1] == boollist_eol_sentry ||
		 (strings[count+1] == set_array_stop &&
		  strings[count+2] == boollist_eol_sentry));
#endif
	}
	return strings;

}

void settings_file_get(const char *value, pool_t path_pool,
		       struct settings_file *file_r)
{
	const char *p;

	if (*value == '\0') {
		file_r->path = "";
		file_r->content = "";
		return;
	}

	p = strchr(value, '\n');
	if (p == NULL)
		i_panic("Settings file value is missing LF");
	file_r->path = p_strdup_until(path_pool, value, p);
	file_r->content = p + 1;
}

bool settings_file_has_path(const char *value)
{
	/* value must be in <path><LF><content> format */
	const char *p = strchr(value, '\n');
	if (p == NULL)
		i_panic("Settings file value is missing LF");
	return p != value;
}

const char *settings_file_get_value(pool_t pool,
				    const struct settings_file *file)
{
	const char *path = file->path != NULL ? file->path : "";
	size_t path_len = strlen(path);
	size_t content_len = strlen(file->content);

	char *value = p_malloc(pool, path_len + 1 + content_len + 1);
	memcpy(value, path, path_len);
	value[path_len] = '\n';
	memcpy(value + path_len + 1, file->content, content_len);
	return value;
}

void settings_boollist_finish(ARRAY_TYPE(const_string) *array, bool stop)
{
	array_append_zero(array);
	if (stop)
		array_push_back(array, &set_array_stop);
#ifdef DEBUG
	array_push_back(array, &boollist_eol_sentry);
	array_pop_back(array);
#endif
	if (stop)
		array_pop_back(array);
	array_pop_back(array);
}

bool settings_boollist_is_stopped(const ARRAY_TYPE(const_string) *array)
{
	/* The first element after the visible array is NULL. If the next element
	   after the NULL is set_array_stop, then the boollist is stopped. */
	unsigned int count;
	const char *const *values = array_get(array, &count);
	i_assert(values[count] == NULL);
	return values[count + 1] == set_array_stop;
}

static int
settings_parse_boollist(struct setting_parser_context *ctx,
			ARRAY_TYPE(const_string) *array,
			const char *key, const char *value)
{
	const char *const *elem, *error;

	if (!array_is_created(array))
		p_array_init(array, ctx->set_pool, 5);
	else {
		/* If the array is stopped, then the boollist should not
		   be modified any further. */
		if (settings_boollist_is_stopped(array))
			return 0;
	}

	key = strrchr(key, SETTINGS_SEPARATOR);
	if (key == NULL) {
		/* replace the whole boollist */
		array_clear(array);
		if (settings_parse_boollist_string(value, ctx->set_pool,
						   array, &error) < 0) {
			settings_parser_set_error(ctx, error);
			return -1;
		}
		/* keep it NULL-terminated for each access */
		settings_boollist_finish(array, FALSE);
		return 0;
	}
	key = settings_section_unescape(key + 1);

	bool value_bool;
	if (get_bool(ctx, value, &value_bool) < 0)
		return -1;

	elem = array_lsearch(array, &key, i_strcmp_p);
	if (elem == NULL && value_bool) {
		/* add missing element */
		key = p_strdup(ctx->set_pool, key);
		array_push_back(array, &key);
	} else if (!value_bool) {
		/* remove unwanted element */
		if (elem != NULL) {
			key = *elem;
			array_delete(array, array_ptr_to_idx(array, elem), 1);
		} else {
			key = p_strdup(ctx->parser_pool, key);
		}
		/* remember the removal for settings_parse_list_has_key() */
		if (!array_is_created(&ctx->boollist_removals))
			p_array_init(&ctx->boollist_removals, ctx->parser_pool, 2);
		struct boollist_removal *removal =
			array_append_space(&ctx->boollist_removals);
		removal->array = array;
		removal->key_suffix = key;
	}
	/* keep it NULL-terminated for each access */
	settings_boollist_finish(array, FALSE);
	return 0;
}

static int
settings_parse(struct setting_parser_context *ctx,
	       const struct setting_define *def,
	       const char *key, const char *value, bool dup_value)
{
	void *ptr;
	const void *ptr2;
	const char *error;
	int ret;

	if (value == set_value_unknown) {
		/* setting value is unknown - preserve the exact pointer */
		dup_value = FALSE;
	}

	i_free(ctx->error);

	while (def->type == SET_ALIAS) {
		i_assert(def != ctx->info->defines);
		def--;
	}

	ptr = PTR_OFFSET(ctx->set_struct, def->offset);
	switch (def->type) {
	case SET_BOOL:
		if (get_bool(ctx, value, (bool *)ptr) < 0)
			return -1;
		break;
	case SET_UINTMAX:
		if (get_uintmax(ctx, value, (uintmax_t *)ptr) < 0)
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
		if (settings_value_is_unlimited(value)) {
			*(unsigned int *)ptr = SET_TIME_INFINITE;
			return 0;
		}
		if (str_parse_get_interval(value, (unsigned int *)ptr, &error) < 0) {
			settings_parser_set_error(ctx, error);
			return -1;
		}
		break;
	case SET_TIME_MSECS:
		if (settings_value_is_unlimited(value)) {
			*(unsigned int *)ptr = SET_TIME_MSECS_INFINITE;
			return 0;
		}
		if (str_parse_get_interval_msecs(value, (unsigned int *)ptr, &error) < 0) {
			settings_parser_set_error(ctx, error);
			return -1;
		}
		break;
	case SET_SIZE:
		if (settings_value_is_unlimited(value)) {
			*(uoff_t *)ptr = SET_SIZE_UNLIMITED;
			return 0;
		}
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
	case SET_STR_NOVARS:
		if (dup_value)
			value = p_strdup(ctx->set_pool, value);
		*((const char **)ptr) = value;
		break;
	case SET_FILE: {
		/* only expand first line, if there */
		const char *path = t_strcut(value, '\n');
		if (strstr(path, "%{") != NULL) {
			if (t_var_expand(value, NULL, &value, &error) < 0) {
				settings_parser_set_error(ctx, error);
				return -1;
			}
		}
		/* Read the file directly to get the content */
		if (get_file(ctx, dup_value, &value) < 0) {
			/* We may be running settings_check()s in doveconf at a
			   time when the file couldn't yet be opened. To avoid
			   unnecessary errors, set the value unknown. */
			*((const char **)ptr) = set_value_unknown;
			return -1;
		}
		*((const char **)ptr) = value;
		break;
	}
	case SET_ENUM:
		/* get the available values from default string */
		i_assert(ctx->info->defaults != NULL);
		ptr2 = CONST_PTR_OFFSET(ctx->info->defaults, def->offset);
		if (get_enum(ctx, value, (char **)ptr,
			     *(const char *const *)ptr2) < 0)
			return -1;
		break;
	case SET_STRLIST:
		T_BEGIN {
			ret = settings_parse_strlist(ctx, ptr, key, value,
						     &error);
			if (ret < 0)
				settings_parser_set_error(ctx, error);
		} T_END;
		if (ret < 0)
			return -1;
		break;
	case SET_BOOLLIST:
		T_BEGIN {
			ret = settings_parse_boollist(ctx, ptr, key, value);
		} T_END;
		if (ret < 0)
			return -1;
		break;
	case SET_FILTER_ARRAY: {
		/* Add filter names to the array. Userdb can add more simply
		   by giving e.g. "namespace+=newname" without it removing the
		   existing ones. */
		ARRAY_TYPE(const_string) *arr = ptr;
		const char *const *list =
			t_strsplit(value, SETTINGS_FILTER_ARRAY_SEPARATORS);
		unsigned int i, count = str_array_length(list);
		if (!array_is_created(arr))
			p_array_init(arr, ctx->set_pool, count);
		else {
			/* If the next element after the visible array is
			   set_array_stop, then the named list filter
			   should not be modified any further. */
			unsigned int old_count;
			const char *const *old_values =
				array_get(arr, &old_count);
			if (old_values[old_count] == set_array_stop)
				break;
		}
		unsigned int insert_pos = 0;
		for (i = 0; i < count; i++) {
			const char *value = p_strdup(ctx->set_pool,
				settings_section_unescape(list[i]));
			if (array_lsearch(arr, &value, i_strcmp_p) != NULL)
				continue; /* ignore duplicates */
			if ((ctx->flags & SETTINGS_PARSER_FLAG_INSERT_FILTERS) != 0)
				array_insert(arr, insert_pos++, &value, 1);
			else
				array_push_back(arr, &value);
		}
		/* Make sure the next element after the array is accessible for
		   the set_array_stop check. */
		array_append_zero(arr);
		array_pop_back(arr);
		break;
	}
	case SET_FILTER_NAME:
		settings_parser_set_error(ctx, t_strdup_printf(
			"Setting is a named filter, use '%s {'", key));
		return -1;
	case SET_ALIAS:
		i_unreached();
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

	/* try to find list/key prefix */
	end = strrchr(key, SETTINGS_SEPARATOR);
	if (end == NULL)
		return FALSE;

	parent_key = t_strdup_until(key, end);
	def = setting_define_find(ctx->info, parent_key);
	if (def != NULL && (def->type == SET_STRLIST ||
			    def->type == SET_BOOLLIST)) {
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

void settings_parse_array_stop(struct setting_parser_context *ctx,
			       unsigned int key_idx)
{
	i_assert(ctx->info->defines[key_idx].type == SET_FILTER_ARRAY ||
		 ctx->info->defines[key_idx].type == SET_BOOLLIST ||
		 ctx->info->defines[key_idx].type == SET_STRLIST);

	ARRAY_TYPE(const_string) *arr =
		PTR_OFFSET(ctx->set_struct, ctx->info->defines[key_idx].offset);
	if (!array_is_created(arr))
		p_array_init(arr, ctx->set_pool, 1);

	if (ctx->info->defines[key_idx].type == SET_BOOLLIST)
		settings_boollist_finish(arr, TRUE);
	else {
		/* Use the next element hidden after the array to keep
		   the stop-state */
		array_push_back(arr, &set_array_stop);
		array_pop_back(arr);
	}
}

static int boollist_removal_cmp(const struct boollist_removal *r1,
				const struct boollist_removal *r2)
{
	if (r1->array != r2->array)
		return 1;
	return strcmp(r1->key_suffix, r2->key_suffix);
}

bool settings_parse_list_has_key(struct setting_parser_context *ctx,
				 unsigned int key_idx,
				 const char *key_suffix)
{
	const struct setting_define *def = &ctx->info->defines[key_idx];
	unsigned int skip = UINT_MAX;

	switch (def->type) {
	case SET_STRLIST:
		skip = 2;
		break;
	case SET_BOOLLIST:
		skip = 1;
		if (!array_is_created(&ctx->boollist_removals))
			break;

		struct boollist_removal lookup = {
			.array = PTR_OFFSET(ctx->set_struct, def->offset),
			.key_suffix = key_suffix,
		};
		if (array_lsearch(&ctx->boollist_removals, &lookup,
				  boollist_removal_cmp) != NULL)
			return TRUE;
		break;
	default:
		i_unreached();
	}

	ARRAY_TYPE(const_string) *array =
		PTR_OFFSET(ctx->set_struct, def->offset);
	if (!array_is_created(array))
		return FALSE;

	unsigned int i, count;
	const char *const *items = array_get(array, &count);
	for (i = 0; i < count; i += skip) {
		if (strcmp(items[i], key_suffix) == 0)
			return TRUE;
	}
	return FALSE;
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
		   lists don't have aliases, because the key replacement
		   would only need to replace the key prefix then. */
		i_assert(def->type != SET_STRLIST && def->type != SET_BOOLLIST);
		*key = def->key;
	}
	*type_r = def->type;
	return PTR_OFFSET(ctx->set_struct, def->offset);
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

unsigned int settings_hash(const struct setting_parser_info *info,
			   const void *set, const char *const *except_fields)
{
	unsigned int crc = 0;

	for (unsigned int i = 0; info->defines[i].key != NULL; i++) {
		if (except_fields != NULL &&
		    str_array_find(except_fields, info->defines[i].key))
			continue;

		const void *p = CONST_PTR_OFFSET(set, info->defines[i].offset);
		switch (info->defines[i].type) {
		case SET_BOOL: {
			const bool *b = p;
			crc = crc32_data_more(crc, b, sizeof(*b));
			break;
		}
		case SET_UINTMAX: {
			const uintmax_t *i = p;
			crc = crc32_data_more(crc, i, sizeof(*i));
			break;
		}
		case SET_UINT:
		case SET_UINT_OCT:
		case SET_TIME:
		case SET_TIME_MSECS: {
			const unsigned int *i = p;
			crc = crc32_data_more(crc, i, sizeof(*i));
			break;
		}
		case SET_SIZE: {
			const uoff_t *s = p;
			crc = crc32_data_more(crc, s, sizeof(*s));
			break;
		}
		case SET_IN_PORT: {
			const in_port_t *port = p;
			crc = crc32_data_more(crc, port, sizeof(*port));
			break;
		}
		case SET_STR:
		case SET_STR_NOVARS:
		case SET_ENUM: {
			const char *const *str = p;
			crc = crc32_str_more(crc, *str);
			break;
		}
		case SET_FILE: {
			const char *const *str = p;
			const char *lf = strchr(*str, '\n');
			if (lf == NULL)
				i_panic("Settings file value is missing LF");
			if (lf == *str) {
				/* no filename - need to hash the content */
				crc = crc32_str_more(crc, *str + 1);
			} else {
				/* hashing the filename is enough */
				crc = crc32_data_more(crc, *str, lf - *str);
			}
			break;
		}
		case SET_STRLIST:
		case SET_BOOLLIST:
		case SET_FILTER_ARRAY: {
			const ARRAY_TYPE(const_string) *list = p;
			if (array_is_created(list)) {
				const char *str;
				array_foreach_elem(list, str)
					crc = crc32_str_more(crc, str);
			}
			break;
		}
		case SET_ALIAS:
		case SET_FILTER_NAME:
			break;
		}
	}
	return crc;
}

bool settings_equal(const struct setting_parser_info *info,
		    const void *set1, const void *set2,
		    const char *const *except_fields)
{
	for (unsigned int i = 0; info->defines[i].key != NULL; i++) {
		if (except_fields != NULL &&
		    str_array_find(except_fields, info->defines[i].key))
			continue;

		const void *p1 = CONST_PTR_OFFSET(set1, info->defines[i].offset);
		const void *p2 = CONST_PTR_OFFSET(set2, info->defines[i].offset);
		switch (info->defines[i].type) {
		case SET_BOOL: {
			const bool *b1 = p1, *b2 = p2;
			if (*b1 != *b2)
				return FALSE;
			break;
		}
		case SET_UINTMAX: {
			const uintmax_t *i1 = p1, *i2 = p2;
			if (*i1 != *i2)
				return FALSE;
			break;
		}
		case SET_UINT:
		case SET_UINT_OCT:
		case SET_TIME:
		case SET_TIME_MSECS: {
			const unsigned int *i1 = p1, *i2 = p2;
			if (*i1 != *i2)
				return FALSE;
			break;
		}
		case SET_SIZE: {
			const uoff_t *s1 = p1, *s2 = p2;
			if (*s1 != *s2)
				return FALSE;
			break;
		}
		case SET_IN_PORT: {
			const in_port_t *port1 = p1, *port2 = p2;
			if (*port1 != *port2)
				return FALSE;
			break;
		}
		case SET_STR:
		case SET_STR_NOVARS:
		case SET_ENUM:
		case SET_FILE: {
			const char *const *str1 = p1, *const *str2 = p2;
			if (strcmp(*str1, *str2) != 0)
				return FALSE;
			break;
		}
		case SET_STRLIST:
		case SET_BOOLLIST:
		case SET_FILTER_ARRAY: {
			const ARRAY_TYPE(const_string) *list1 = p1, *list2 = p2;
			if (array_is_empty(list1)) {
				if (!array_is_empty(list2))
					return FALSE;
				break;
			}
			if (array_is_empty(list2))
				return FALSE;

			unsigned int i, count1, count2;
			const char *const *str1 = array_get(list1, &count1);
			const char *const *str2 = array_get(list2, &count2);
			if (count1 != count2)
				return FALSE;
			for (i = 0; i < count1; i++) {
				if (strcmp(str1[i], str2[i]) != 0)
					return FALSE;
			}
			break;
		}
		case SET_ALIAS:
		case SET_FILTER_NAME:
			break;
		}
	}
	return TRUE;
}

void *settings_defaults_dup(pool_t pool, const struct setting_parser_info *info)
{
	void *dup = p_malloc(pool, info->struct_size);
	memcpy(dup, info->defaults, info->struct_size);
	memcpy(PTR_OFFSET(dup, info->pool_offset1 - 1), &pool, sizeof(pool));
	return dup;
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

static enum settings_binary config_binary = SETTINGS_BINARY_OTHER;

void settings_set_config_binary(enum settings_binary binary)
{
	config_binary = binary;
}

enum settings_binary settings_get_config_binary(void)
{
	return config_binary;
}

