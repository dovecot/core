/* Copyright (c) 2005-2016 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "istream.h"
#include "hex-binary.h"
#include "str.h"
#include "sql-api-private.h"
#include "sql-db-cache.h"
#include "dict-private.h"
#include "dict-sql-settings.h"
#include "dict-sql.h"

#include <unistd.h>
#include <fcntl.h>

#define DICT_SQL_MAX_UNUSED_CONNECTIONS 10

enum sql_recurse_type {
	SQL_DICT_RECURSE_NONE,
	SQL_DICT_RECURSE_ONE,
	SQL_DICT_RECURSE_FULL
};

struct sql_dict {
	struct dict dict;

	pool_t pool;
	struct sql_db *db;
	const char *username;
	const struct dict_sql_settings *set;

	unsigned int has_on_duplicate_key:1;
};

struct sql_dict_iterate_context {
	struct dict_iterate_context ctx;
	pool_t pool;

	enum dict_iterate_flags flags;
	const char **paths;

	struct sql_result *result;
	string_t *key;
	const struct dict_sql_map *map;
	unsigned int key_prefix_len, pattern_prefix_len, next_map_idx;
	unsigned int path_idx, sql_fields_start_idx;
	bool synchronous_result;
	bool failed;
};

struct sql_dict_inc_row {
	struct sql_dict_inc_row *prev;
	unsigned int rows;
};

struct sql_dict_transaction_context {
	struct dict_transaction_context ctx;

	struct sql_transaction_context *sql_ctx;

	const struct dict_sql_map *prev_inc_map;
	char *prev_inc_key;
	long long prev_inc_diff;
	pool_t inc_row_pool;
	struct sql_dict_inc_row *inc_row;

	dict_transaction_commit_callback_t *async_callback;
	void *async_context;

	unsigned int failed:1;
};

static struct sql_db_cache *dict_sql_db_cache;

static void sql_dict_prev_inc_flush(struct sql_dict_transaction_context *ctx);

static int
sql_dict_init(struct dict *driver, const char *uri,
	      const struct dict_settings *set,
	      struct dict **dict_r, const char **error_r)
{
	struct sql_dict *dict;
	pool_t pool;

	pool = pool_alloconly_create("sql dict", 2048);
	dict = p_new(pool, struct sql_dict, 1);
	dict->pool = pool;
	dict->dict = *driver;
	dict->username = p_strdup(pool, set->username);
	dict->set = dict_sql_settings_read(uri, error_r);
	if (dict->set == NULL) {
		pool_unref(&pool);
		return -1;
	}

	/* currently pgsql and sqlite don't support "ON DUPLICATE KEY" */
	dict->has_on_duplicate_key = strcmp(driver->name, "mysql") == 0;

	dict->db = sql_db_cache_new(dict_sql_db_cache, driver->name,
				    dict->set->connect);
	*dict_r = &dict->dict;
	return 0;
}

static void sql_dict_deinit(struct dict *_dict)
{
	struct sql_dict *dict = (struct sql_dict *)_dict;

	sql_deinit(&dict->db);
	pool_unref(&dict->pool);
}

static int sql_dict_wait(struct dict *dict ATTR_UNUSED)
{
	/* FIXME: lib-sql doesn't support this yet */
	return 0;
}

static bool
dict_sql_map_match(const struct dict_sql_map *map, const char *path,
		   ARRAY_TYPE(const_string) *values, unsigned int *pat_len_r,
		   unsigned int *path_len_r, bool partial_ok, bool recurse)
{
	const char *path_start = path;
	const char *pat, *field, *p;
	unsigned int len;

	array_clear(values);
	pat = map->pattern;
	while (*pat != '\0' && *path != '\0') {
		if (*pat == '$') {
			/* variable */
			pat++;
			if (*pat == '\0') {
				/* pattern ended with this variable,
				   it'll match the rest of the path */
				len = strlen(path);
				if (partial_ok) {
					/* iterating - the last field never
					   matches fully. if there's a trailing
					   '/', drop it. */
					pat--;
					if (path[len-1] == '/') {
						field = t_strndup(path, len-1);
						array_append(values, &field, 1);
					} else {
						array_append(values, &path, 1);
					}
				} else {
					array_append(values, &path, 1);
					path += len;
				}
				*path_len_r = path - path_start;
				*pat_len_r = pat - map->pattern;
				return TRUE;
			}
			/* pattern matches until the next '/' in path */
			p = strchr(path, '/');
			if (p != NULL) {
				field = t_strdup_until(path, p);
				array_append(values, &field, 1);
				path = p;
			} else {
				/* no '/' anymore, but it'll still match a
				   partial */
				array_append(values, &path, 1);
				path += strlen(path);
				pat++;
			}
		} else if (*pat == *path) {
			pat++;
			path++;
		} else {
			return FALSE;
		}
	}

	*path_len_r = path - path_start;
	*pat_len_r = pat - map->pattern;

	if (*pat == '\0')
		return *path == '\0';
	else if (!partial_ok)
		return FALSE;
	else {
		/* partial matches must end with '/'. */
		if (pat != map->pattern && pat[-1] != '/')
			return FALSE;
		/* if we're not recursing, there should be only one $variable
		   left. */
		if (recurse)
			return TRUE;
		return pat[0] == '$' && strchr(pat, '/') == NULL;
	}
}

static const struct dict_sql_map *
sql_dict_find_map(struct sql_dict *dict, const char *path,
		  ARRAY_TYPE(const_string) *values)
{
	const struct dict_sql_map *maps;
	unsigned int i, count, len;

	t_array_init(values, dict->set->max_field_count);
	maps = array_get(&dict->set->maps, &count);
	for (i = 0; i < count; i++) {
		if (dict_sql_map_match(&maps[i], path, values,
				       &len, &len, FALSE, FALSE))
			return &maps[i];
	}
	return NULL;
}

static int
sql_dict_value_escape(string_t *str, struct sql_dict *dict,
		      enum dict_sql_type value_type, const char *field_name,
		      const char *value, const char *value_suffix,
		      const char **error_r)
{
	buffer_t *buf;
	unsigned int num;

	switch (value_type) {
	case DICT_SQL_TYPE_STRING:
		str_printfa(str, "'%s%s'", sql_escape_string(dict->db, value),
			    value_suffix);
		return 0;
	case DICT_SQL_TYPE_UINT:
		if (value_suffix[0] != '\0' || str_to_uint(value, &num) < 0) {
			*error_r = t_strdup_printf(
				"field %s value isn't unsigned integer: %s%s",
				field_name, value, value_suffix);
			return -1;
		}
		str_printfa(str, "%u", num);
		return 0;
	case DICT_SQL_TYPE_HEXBLOB:
		break;
	}

	buf = buffer_create_dynamic(pool_datastack_create(), strlen(value)/2);
	if (hex_to_binary(value, buf) < 0) {
		/* we shouldn't get untrusted input here. it's also a bit
		   annoying to handle this error. */
		*error_r = t_strdup_printf("field %s value isn't hexblob: %s",
					   field_name, value);
		return -1;
	}
	str_append(buf, value_suffix);
	str_append(str, sql_escape_blob(dict->db, buf->data, buf->used));
	return 0;
}

static int
sql_dict_field_escape_value(string_t *str, struct sql_dict *dict,
			    const struct dict_sql_field *field,
			    const char *value, const char *value_suffix,
			    const char **error_r)
{
	return sql_dict_value_escape(str, dict, field->value_type,
				     field->name, value, value_suffix, error_r);
}

static int
sql_dict_where_build(struct sql_dict *dict, const struct dict_sql_map *map,
		     const ARRAY_TYPE(const_string) *values_arr,
		     char key1, enum sql_recurse_type recurse_type,
		     string_t *query, const char **error_r)
{
	const struct dict_sql_field *sql_fields;
	const char *const *values;
	unsigned int i, count, count2, exact_count;
	bool priv = key1 == DICT_PATH_PRIVATE[0];

	sql_fields = array_get(&map->sql_fields, &count);
	values = array_get(values_arr, &count2);
	/* if we came here from iteration code there may be less values */
	i_assert(count2 <= count);

	if (count2 == 0 && !priv) {
		/* we want everything */
		return 0;
	}

	str_append(query, " WHERE");
	exact_count = count == count2 && recurse_type != SQL_DICT_RECURSE_NONE ?
		count2-1 : count2;
	for (i = 0; i < exact_count; i++) {
		if (i > 0)
			str_append(query, " AND");
		str_printfa(query, " %s = ", sql_fields[i].name);
		if (sql_dict_field_escape_value(query, dict, &sql_fields[i],
						values[i], "", error_r) < 0)
			return -1;
	}
	switch (recurse_type) {
	case SQL_DICT_RECURSE_NONE:
		break;
	case SQL_DICT_RECURSE_ONE:
		if (i > 0)
			str_append(query, " AND");
		if (i < count2) {
			str_printfa(query, " %s LIKE ", sql_fields[i].name);
			if (sql_dict_field_escape_value(query, dict, &sql_fields[i],
							values[i], "/%", error_r) < 0)
				return -1;
			str_printfa(query, " AND %s NOT LIKE ", sql_fields[i].name);
			if (sql_dict_field_escape_value(query, dict, &sql_fields[i],
							values[i], "/%/%", error_r) < 0)
				return -1;
		} else {
			str_printfa(query, " %s LIKE '%%' AND "
				    "%s NOT LIKE '%%/%%'",
				    sql_fields[i].name, sql_fields[i].name);
		}
		break;
	case SQL_DICT_RECURSE_FULL:
		if (i < count2) {
			if (i > 0)
				str_append(query, " AND");
			str_printfa(query, " %s LIKE ",
				    sql_fields[i].name);
			if (sql_dict_field_escape_value(query, dict, &sql_fields[i],
							values[i], "/%", error_r) < 0)
				return -1;
		}
		break;
	}
	if (priv) {
		if (count2 > 0)
			str_append(query, " AND");
		str_printfa(query, " %s = '%s'", map->username_field,
			    sql_escape_string(dict->db, dict->username));
	}
	return 0;
}

static int
sql_lookup_get_query(struct sql_dict *dict, const char *key,
		     string_t *query, const struct dict_sql_map **map_r,
		     const char **error_r)
{
	const struct dict_sql_map *map;
	ARRAY_TYPE(const_string) values;
	const char *error;

	map = *map_r = sql_dict_find_map(dict, key, &values);
	if (map == NULL) {
		*error_r = t_strdup_printf(
			"sql dict lookup: Invalid/unmapped key: %s", key);
		return -1;
	}
	str_printfa(query, "SELECT %s FROM %s",
		    map->value_field, map->table);
	if (sql_dict_where_build(dict, map, &values, key[0],
				 SQL_DICT_RECURSE_NONE, query, &error) < 0) {
		*error_r = t_strdup_printf(
			"sql dict lookup: Failed to lookup key %s: %s", key, error);
		return -1;
	}
	return 0;
}

static const char *
sql_dict_result_unescape(enum dict_sql_type type, pool_t pool,
			 struct sql_result *result, unsigned int result_idx)
{
	const unsigned char *data;
	size_t size;
	string_t *str;

	switch (type) {
	case DICT_SQL_TYPE_STRING:
	case DICT_SQL_TYPE_UINT:
		return p_strdup(pool, sql_result_get_field_value(result, result_idx));
	case DICT_SQL_TYPE_HEXBLOB:
		break;
	}

	data = sql_result_get_field_value_binary(result, result_idx, &size);
	str = str_new(pool, size*2 + 1);
	binary_to_hex_append(str, data, size);
	return str_c(str);
}

static enum dict_sql_type 
sql_dict_map_type(const struct dict_sql_map *map)
{
	if (map->value_type != NULL) {
		if (strcmp(map->value_type, "string") == 0)
			return DICT_SQL_TYPE_STRING;
		if (strcmp(map->value_type, "hexblob") == 0)
			return DICT_SQL_TYPE_HEXBLOB;
		if (strcmp(map->value_type, "uint") == 0)
			return DICT_SQL_TYPE_UINT;
		i_unreached(); /* should have checked already at parsing */
	}
	return map->value_hexblob ? DICT_SQL_TYPE_HEXBLOB : DICT_SQL_TYPE_STRING;
}

static const char *
sql_dict_result_unescape_value(const struct dict_sql_map *map, pool_t pool,
			       struct sql_result *result)
{
	return sql_dict_result_unescape(sql_dict_map_type(map), pool, result, 0);
}

static const char *
sql_dict_result_unescape_field(const struct dict_sql_map *map, pool_t pool,
			       struct sql_result *result, unsigned int result_idx,
			       unsigned int sql_field_idx)
{
	const struct dict_sql_field *sql_field;

	sql_field = array_idx(&map->sql_fields, sql_field_idx);
	return sql_dict_result_unescape(sql_field->value_type, pool,
					result, result_idx);
}

static int sql_dict_lookup(struct dict *_dict, pool_t pool,
			   const char *key, const char **value_r)
{
	struct sql_dict *dict = (struct sql_dict *)_dict;
	const struct dict_sql_map *map;
	struct sql_result *result = NULL;
	int ret;

	T_BEGIN {
		string_t *query = t_str_new(256);
		const char *error;

		ret = sql_lookup_get_query(dict, key, query, &map, &error);
		if (ret < 0)
			i_error("%s", error);
		else
			result = sql_query_s(dict->db, str_c(query));
	} T_END;

	if (ret < 0) {
		*value_r = NULL;
		return -1;
	}

	ret = sql_result_next_row(result);
	if (ret <= 0) {
		if (ret < 0) {
			i_error("dict sql lookup failed: %s",
				sql_result_get_error(result));
		}
		*value_r = NULL;
	} else {
		*value_r = sql_dict_result_unescape_value(map, pool, result);
	}

	sql_result_unref(result);
	return ret;
}

struct sql_dict_lookup_context {
	const struct dict_sql_map *map;
	dict_lookup_callback_t *callback;
	void *context;
};

static void
sql_dict_lookup_async_callback(struct sql_result *sql_result,
			       struct sql_dict_lookup_context *ctx)
{
	struct dict_lookup_result result;

	memset(&result, 0, sizeof(result));
	result.ret = sql_result_next_row(sql_result);
	if (result.ret < 0)
		result.error = sql_result_get_error(sql_result);
	else if (result.ret > 0) {
		result.value = sql_dict_result_unescape_value(ctx->map,
			pool_datastack_create(), sql_result);
	}
	ctx->callback(&result, ctx->context);

	i_free(ctx);
}

static void
sql_dict_lookup_async(struct dict *_dict, const char *key,
		      dict_lookup_callback_t *callback, void *context)
{
	struct sql_dict *dict = (struct sql_dict *)_dict;
	const struct dict_sql_map *map;
	struct sql_dict_lookup_context *ctx;

	T_BEGIN {
		string_t *query = t_str_new(256);
		const char *error;

		if (sql_lookup_get_query(dict, key, query, &map, &error) < 0) {
			struct dict_lookup_result result;

			memset(&result, 0, sizeof(result));
			result.ret = -1;
			result.error = error;
			callback(&result, context);
		} else {
			ctx = i_new(struct sql_dict_lookup_context, 1);
			ctx->callback = callback;
			ctx->context = context;
			ctx->map = map;
			sql_query(dict->db, str_c(query),
				  sql_dict_lookup_async_callback, ctx);
		}
	} T_END;
}

static const struct dict_sql_map *
sql_dict_iterate_find_next_map(struct sql_dict_iterate_context *ctx,
			       ARRAY_TYPE(const_string) *values)
{
	struct sql_dict *dict = (struct sql_dict *)ctx->ctx.dict;
	const struct dict_sql_map *maps;
	unsigned int i, count, pat_len, path_len;
	bool recurse = (ctx->flags & DICT_ITERATE_FLAG_RECURSE) != 0;

	t_array_init(values, dict->set->max_field_count);
	maps = array_get(&dict->set->maps, &count);
	for (i = ctx->next_map_idx; i < count; i++) {
		if (dict_sql_map_match(&maps[i], ctx->paths[ctx->path_idx],
				       values, &pat_len, &path_len, TRUE, recurse) &&
		    (recurse ||
		     array_count(values)+1 >= array_count(&maps[i].sql_fields))) {
			ctx->key_prefix_len = path_len;
			ctx->pattern_prefix_len = pat_len;
			ctx->next_map_idx = i + 1;

			str_truncate(ctx->key, 0);
			str_append(ctx->key, ctx->paths[ctx->path_idx]);
			return &maps[i];
		}
	}

	/* try the next path, if there is any */
	ctx->path_idx++;
	if (ctx->paths[ctx->path_idx] != NULL)
		return sql_dict_iterate_find_next_map(ctx, values);
	return NULL;
}

static int
sql_dict_iterate_build_next_query(struct sql_dict_iterate_context *ctx,
				  string_t *query, const char **error_r)
{
	struct sql_dict *dict = (struct sql_dict *)ctx->ctx.dict;
	const struct dict_sql_map *map;
	ARRAY_TYPE(const_string) values;
	const struct dict_sql_field *sql_fields;
	enum sql_recurse_type recurse_type;
	unsigned int i, count;

	map = sql_dict_iterate_find_next_map(ctx, &values);
	if (map == NULL) {
		*error_r = "Invalid/unmapped path";
		return 0;
	}

	if (ctx->result != NULL) {
		sql_result_unref(ctx->result);
		ctx->result = NULL;
	}

	str_append(query, "SELECT ");
	if ((ctx->flags & DICT_ITERATE_FLAG_NO_VALUE) == 0)
		str_printfa(query, "%s,", map->value_field);

	/* get all missing fields */
	sql_fields = array_get(&map->sql_fields, &count);
	i = array_count(&values);
	if (i == count) {
		/* we always want to know the last field since we're
		   iterating its children */
		i_assert(i > 0);
		i--;
	}
	ctx->sql_fields_start_idx = i;
	for (; i < count; i++)
		str_printfa(query, "%s,", sql_fields[i].name);
	str_truncate(query, str_len(query)-1);

	str_printfa(query, " FROM %s", map->table);

	if ((ctx->flags & DICT_ITERATE_FLAG_RECURSE) != 0)
		recurse_type = SQL_DICT_RECURSE_FULL;
	else if ((ctx->flags & DICT_ITERATE_FLAG_EXACT_KEY) != 0)
		recurse_type = SQL_DICT_RECURSE_NONE;
	else
		recurse_type = SQL_DICT_RECURSE_ONE;
	if (sql_dict_where_build(dict, map, &values,
				 ctx->paths[ctx->path_idx][0],
				 recurse_type, query, error_r) < 0)
		return -1;

	if ((ctx->flags & DICT_ITERATE_FLAG_SORT_BY_KEY) != 0) {
		str_append(query, " ORDER BY ");
		for (i = 0; i < count; i++) {
			str_printfa(query, "%s", sql_fields[i].name);
			if (i < count-1)
				str_append_c(query, ',');
		}
	} else if ((ctx->flags & DICT_ITERATE_FLAG_SORT_BY_VALUE) != 0)
		str_printfa(query, " ORDER BY %s", map->value_field);

	ctx->map = map;
	return 1;
}

static void sql_dict_iterate_callback(struct sql_result *result,
				      struct sql_dict_iterate_context *ctx)
{
	sql_result_ref(result);
	ctx->result = result;
	if (ctx->ctx.async_callback != NULL && !ctx->synchronous_result)
		ctx->ctx.async_callback(ctx->ctx.async_context);
}

static int sql_dict_iterate_next_query(struct sql_dict_iterate_context *ctx,
				       const char **error_r)
{
	struct sql_dict *dict = (struct sql_dict *)ctx->ctx.dict;
	char *error = NULL;
	int ret;

	T_BEGIN {
		string_t *query = t_str_new(256);

		ret = sql_dict_iterate_build_next_query(ctx, query, error_r);
		if (ret <= 0) {
			/* failed */
			error = i_strdup(*error_r);
		} else if ((ctx->flags & DICT_ITERATE_FLAG_ASYNC) == 0) {
			ctx->result = sql_query_s(dict->db, str_c(query));
		} else {
			i_assert(ctx->result == NULL);
			ctx->synchronous_result = TRUE;
			sql_query(dict->db, str_c(query),
				  sql_dict_iterate_callback, ctx);
			ctx->synchronous_result = FALSE;
		}
	} T_END;
	*error_r = t_strdup(error);
	i_free(error);
	return ret;
}

static struct dict_iterate_context *
sql_dict_iterate_init(struct dict *_dict, const char *const *paths,
		      enum dict_iterate_flags flags)
{
	struct sql_dict_iterate_context *ctx;
	unsigned int i, path_count;
	const char *error;
	pool_t pool;

	pool = pool_alloconly_create("sql dict iterate", 512);
	ctx = p_new(pool, struct sql_dict_iterate_context, 1);
	ctx->ctx.dict = _dict;
	ctx->pool = pool;
	ctx->flags = flags;

	for (path_count = 0; paths[path_count] != NULL; path_count++) ;
	ctx->paths = p_new(pool, const char *, path_count + 1);
	for (i = 0; i < path_count; i++)
		ctx->paths[i] = p_strdup(pool, paths[i]);

	ctx->key = str_new(pool, 256);
	if (sql_dict_iterate_next_query(ctx, &error) <= 0) {
		i_error("sql dict iterate failed for %s: %s",
			paths[0], error);
		ctx->result = NULL;
		ctx->failed = TRUE;
		return &ctx->ctx;
	}
	return &ctx->ctx;
}

static bool sql_dict_iterate(struct dict_iterate_context *_ctx,
			     const char **key_r, const char **value_r)
{
	struct sql_dict_iterate_context *ctx =
		(struct sql_dict_iterate_context *)_ctx;
	const char *p, *value, *error;
	unsigned int i, sql_field_i, count;
	int ret;

	_ctx->has_more = FALSE;
	if (ctx->failed)
		return FALSE;

	for (;;) {
		if (ctx->result == NULL) {
			/* wait for async lookup to finish */
			i_assert((ctx->flags & DICT_ITERATE_FLAG_ASYNC) != 0);
			_ctx->has_more = TRUE;
			return FALSE;
		}

		ret = sql_result_next_row(ctx->result);
		if (ret != 0)
			break;
		/* see if there are more results in the next map.
		   don't do it if we're looking for an exact match, since we
		   already should have handled it. */
		if ((ctx->flags & DICT_ITERATE_FLAG_EXACT_KEY) != 0)
			return FALSE;
		if ((ret = sql_dict_iterate_next_query(ctx, &error)) == 0)
			return FALSE;
	}
	if (ret < 0) {
		ctx->failed = TRUE;
		i_error("dict sql iterate failed: %s",
			sql_result_get_error(ctx->result));
		return FALSE;
	}

	/* convert fetched row to dict key */
	str_truncate(ctx->key, ctx->key_prefix_len);
	if (ctx->key_prefix_len > 0 &&
	    str_c(ctx->key)[ctx->key_prefix_len-1] != '/')
		str_append_c(ctx->key, '/');

	count = sql_result_get_fields_count(ctx->result);
	i = (ctx->flags & DICT_ITERATE_FLAG_NO_VALUE) != 0 ? 0 : 1;
	sql_field_i = ctx->sql_fields_start_idx;
	for (p = ctx->map->pattern + ctx->pattern_prefix_len; *p != '\0'; p++) {
		if (*p != '$')
			str_append_c(ctx->key, *p);
		else {
			i_assert(i < count);
			value = sql_dict_result_unescape_field(ctx->map,
					pool_datastack_create(), ctx->result, i, sql_field_i);
			if (value != NULL)
				str_append(ctx->key, value);
			i++; sql_field_i++;
		}
	}

	*key_r = str_c(ctx->key);
	if ((ctx->flags & DICT_ITERATE_FLAG_NO_VALUE) != 0)
		*value_r = "";
	else {
		*value_r = sql_dict_result_unescape_value(ctx->map,
					pool_datastack_create(), ctx->result);
	}
	return TRUE;
}

static int sql_dict_iterate_deinit(struct dict_iterate_context *_ctx)
{
	struct sql_dict_iterate_context *ctx =
		(struct sql_dict_iterate_context *)_ctx;
	int ret = ctx->failed ? -1 : 0;

	if (ctx->result != NULL)
		sql_result_unref(ctx->result);
	pool_unref(&ctx->pool);
	return ret;
}

static struct dict_transaction_context *
sql_dict_transaction_init(struct dict *_dict)
{
	struct sql_dict *dict = (struct sql_dict *)_dict;
	struct sql_dict_transaction_context *ctx;

	ctx = i_new(struct sql_dict_transaction_context, 1);
	ctx->ctx.dict = _dict;
	ctx->sql_ctx = sql_transaction_begin(dict->db);

	return &ctx->ctx;
}

static void sql_dict_transaction_free(struct sql_dict_transaction_context *ctx)
{
	if (ctx->inc_row_pool != NULL)
		pool_unref(&ctx->inc_row_pool);
	i_free(ctx->prev_inc_key);
	i_free(ctx);
}

static bool
sql_dict_transaction_has_nonexistent(struct sql_dict_transaction_context *ctx)
{
	struct sql_dict_inc_row *inc_row;

	for (inc_row = ctx->inc_row; inc_row != NULL; inc_row = inc_row->prev) {
		i_assert(inc_row->rows != UINT_MAX);
		if (inc_row->rows == 0)
			return TRUE;
	}
	return FALSE;
}

static void
sql_dict_transaction_commit_callback(const char *error,
				     struct sql_dict_transaction_context *ctx)
{
	int ret;

	if (error == NULL)
		ret = sql_dict_transaction_has_nonexistent(ctx) ? 0 : 1;
	else {
		i_error("sql dict: commit failed: %s", error);
		ret = -1;
	}

	if (ctx->async_callback != NULL)
		ctx->async_callback(ret, ctx->async_context);
	sql_dict_transaction_free(ctx);
}

static int
sql_dict_transaction_commit(struct dict_transaction_context *_ctx, bool async,
			    dict_transaction_commit_callback_t *callback,
			    void *context)
{
	struct sql_dict_transaction_context *ctx =
		(struct sql_dict_transaction_context *)_ctx;
	const char *error;
	int ret = 1;

	if (ctx->prev_inc_map != NULL)
		sql_dict_prev_inc_flush(ctx);

	if (ctx->failed) {
		sql_transaction_rollback(&ctx->sql_ctx);
		ret = -1;
	} else if (!_ctx->changed) {
		/* nothing changed, no need to commit */
		sql_transaction_rollback(&ctx->sql_ctx);
	} else if (async) {
		ctx->async_callback = callback;
		ctx->async_context = context;
		sql_transaction_commit(&ctx->sql_ctx,
			sql_dict_transaction_commit_callback, ctx);
		return 1;
	} else {
		if (sql_transaction_commit_s(&ctx->sql_ctx, &error) < 0) {
			i_error("sql dict: commit failed: %s", error);
			ret = -1;
		} else {
			if (sql_dict_transaction_has_nonexistent(ctx))
				ret = 0;
		}
	}
	sql_dict_transaction_free(ctx);

	if (callback != NULL)
		callback(ret, context);
	return ret;
}

static void sql_dict_transaction_rollback(struct dict_transaction_context *_ctx)
{
	struct sql_dict_transaction_context *ctx =
		(struct sql_dict_transaction_context *)_ctx;

	sql_transaction_rollback(&ctx->sql_ctx);
	sql_dict_transaction_free(ctx);
}

struct dict_sql_build_query_field {
	const struct dict_sql_map *map;
	const char *value;
};

struct dict_sql_build_query {
	struct sql_dict *dict;

	ARRAY(struct dict_sql_build_query_field) fields;
	const ARRAY_TYPE(const_string) *extra_values;
	char key1;
	bool inc;
};

static int sql_dict_set_query(const struct dict_sql_build_query *build,
			      const char **query_r, const char **error_r)
{
	struct sql_dict *dict = build->dict;
	const struct dict_sql_build_query_field *fields;
	const struct dict_sql_field *sql_fields;
	const char *const *extra_values;
	unsigned int i, field_count, count, count2;
	string_t *prefix, *suffix;

	fields = array_get(&build->fields, &field_count);
	i_assert(field_count > 0);

	prefix = t_str_new(64);
	suffix = t_str_new(256);
	str_printfa(prefix, "INSERT INTO %s (", fields[0].map->table);
	str_append(suffix, ") VALUES (");
	for (i = 0; i < field_count; i++) {
		if (i > 0) {
			str_append_c(prefix, ',');
			str_append_c(suffix, ',');
		}
		str_append(prefix, fields[i].map->value_field);
		if (build->inc)
			str_append(suffix, fields[i].value);
		else {
			enum dict_sql_type value_type =
				sql_dict_map_type(fields[i].map);
			if (sql_dict_value_escape(suffix, dict, value_type,
				"value", fields[i].value, "", error_r) < 0)
				return -1;
		}
	}
	if (build->key1 == DICT_PATH_PRIVATE[0]) {
		str_printfa(prefix, ",%s", fields[0].map->username_field);
		str_printfa(suffix, ",'%s'",
			    sql_escape_string(dict->db, dict->username));
	}

	/* add the other fields from the key */
	sql_fields = array_get(&fields[0].map->sql_fields, &count);
	extra_values = array_get(build->extra_values, &count2);
	i_assert(count == count2);
	for (i = 0; i < count; i++) {
		str_printfa(prefix, ",%s", sql_fields[i].name);
		str_append_c(suffix, ',');
		if (sql_dict_field_escape_value(suffix, dict, &sql_fields[i],
						extra_values[i], "", error_r) < 0)
			return -1;
	}

	str_append_str(prefix, suffix);
	str_append_c(prefix, ')');
	if (!dict->has_on_duplicate_key) {
		*query_r = str_c(prefix);
		return 0;
	}

	str_append(prefix, " ON DUPLICATE KEY UPDATE ");
	for (i = 0; i < field_count; i++) {
		if (i > 0)
			str_append_c(prefix, ',');
		str_append(prefix, fields[i].map->value_field);
		str_append_c(prefix, '=');
		if (build->inc) {
			str_printfa(prefix, "%s+%s",
				    fields[i].map->value_field,
				    fields[i].value);
		} else {
			enum dict_sql_type value_type =
				sql_dict_map_type(fields[i].map);
			if (sql_dict_value_escape(prefix, dict, value_type,
				"value", fields[i].value, "", error_r) < 0)
				return -1;
		}
	}
	*query_r = str_c(prefix);
	return 0;
}

static int
sql_dict_update_query(const struct dict_sql_build_query *build,
		      const char **query_r, const char **error_r)
{
	struct sql_dict *dict = build->dict;
	const struct dict_sql_build_query_field *fields;
	unsigned int i, field_count;
	string_t *query;

	i_assert(build->inc);

	fields = array_get(&build->fields, &field_count);
	i_assert(field_count > 0);

	query = t_str_new(64);
	str_printfa(query, "UPDATE %s SET ", fields[0].map->table);
	for (i = 0; i < field_count; i++) {
		if (i > 0)
			str_append_c(query, ',');
		str_printfa(query, "%s=%s", fields[i].map->value_field,
			    fields[i].map->value_field);
		if (fields[i].value[0] != '-')
			str_append_c(query, '+');
		str_append(query, fields[i].value);
	}

	if (sql_dict_where_build(dict, fields[0].map, build->extra_values,
				 build->key1, SQL_DICT_RECURSE_NONE, query, error_r) < 0)
		return -1;
	*query_r = str_c(query);
	return 0;
}

static void sql_dict_set(struct dict_transaction_context *_ctx,
			 const char *key, const char *value)
{
	struct sql_dict_transaction_context *ctx =
		(struct sql_dict_transaction_context *)_ctx;
	struct sql_dict *dict = (struct sql_dict *)_ctx->dict;
	const struct dict_sql_map *map;
	ARRAY_TYPE(const_string) values;

	map = sql_dict_find_map(dict, key, &values);
	if (map == NULL) {
		i_error("sql dict set: Invalid/unmapped key: %s", key);
		ctx->failed = TRUE;
		return;
	}

	if (ctx->prev_inc_map != NULL)
		sql_dict_prev_inc_flush(ctx);

	T_BEGIN {
		struct dict_sql_build_query build;
		struct dict_sql_build_query_field field;
		const char *query, *error;

		field.map = map;
		field.value = value;

		memset(&build, 0, sizeof(build));
		build.dict = dict;
		t_array_init(&build.fields, 1);
		array_append(&build.fields, &field, 1);
		build.extra_values = &values;
		build.key1 = key[0];

		if (sql_dict_set_query(&build, &query, &error) < 0) {
			i_error("dict-sql: Failed to set %s=%s: %s",
				key, value, error);
			ctx->failed = TRUE;
		} else {
			sql_update(ctx->sql_ctx, query);
		}
	} T_END;
}

static void sql_dict_unset(struct dict_transaction_context *_ctx,
			   const char *key)
{
	struct sql_dict_transaction_context *ctx =
		(struct sql_dict_transaction_context *)_ctx;
	struct sql_dict *dict = (struct sql_dict *)_ctx->dict;
	const struct dict_sql_map *map;
	ARRAY_TYPE(const_string) values;

	if (ctx->prev_inc_map != NULL)
		sql_dict_prev_inc_flush(ctx);

	map = sql_dict_find_map(dict, key, &values);
	if (map == NULL) {
		i_error("sql dict unset: Invalid/unmapped key: %s", key);
		ctx->failed = TRUE;
		return;
	}

	T_BEGIN {
		string_t *query = t_str_new(256);
		const char *error;

		str_printfa(query, "DELETE FROM %s", map->table);
		if (sql_dict_where_build(dict, map, &values, key[0],
					 SQL_DICT_RECURSE_NONE, query, &error) < 0) {
			i_error("dict-sql: Failed to delete %s: %s", key, error);
			ctx->failed = TRUE;
		} else {
			sql_update(ctx->sql_ctx, str_c(query));
		}
	} T_END;
}

static void
sql_dict_append(struct dict_transaction_context *_ctx,
		const char *key ATTR_UNUSED, const char *value ATTR_UNUSED)
{
	struct sql_dict_transaction_context *ctx =
		(struct sql_dict_transaction_context *)_ctx;

	i_error("sql dict: Append command not implemented currently");
	ctx->failed = TRUE;
}

static unsigned int *
sql_dict_next_inc_row(struct sql_dict_transaction_context *ctx)
{
	struct sql_dict_inc_row *row;

	if (ctx->inc_row_pool == NULL) {
		ctx->inc_row_pool =
			pool_alloconly_create("sql dict inc rows", 128);
	}
	row = p_new(ctx->inc_row_pool, struct sql_dict_inc_row, 1);
	row->prev = ctx->inc_row;
	row->rows = UINT_MAX;
	ctx->inc_row = row;
	return &row->rows;
}

static void sql_dict_atomic_inc_real(struct sql_dict_transaction_context *ctx,
				     const char *key, long long diff)
{
	struct sql_dict *dict = (struct sql_dict *)ctx->ctx.dict;
	const struct dict_sql_map *map;
	ARRAY_TYPE(const_string) values;

	map = sql_dict_find_map(dict, key, &values);
	i_assert(map != NULL);

	T_BEGIN {
		struct dict_sql_build_query build;
		struct dict_sql_build_query_field field;
		const char *query, *error;

		field.map = map;
		field.value = t_strdup_printf("%lld", diff);

		memset(&build, 0, sizeof(build));
		build.dict = dict;
		t_array_init(&build.fields, 1);
		array_append(&build.fields, &field, 1);
		build.extra_values = &values;
		build.key1 = key[0];
		build.inc = TRUE;

		if (sql_dict_update_query(&build, &query, &error) < 0) {
			i_error("dict-sql: Failed to increase %s: %s", key, error);
			ctx->failed = TRUE;
		} else {
			sql_update_get_rows(ctx->sql_ctx, query,
					    sql_dict_next_inc_row(ctx));
		}
	} T_END;
}

static void sql_dict_prev_inc_flush(struct sql_dict_transaction_context *ctx)
{
	sql_dict_atomic_inc_real(ctx, ctx->prev_inc_key, ctx->prev_inc_diff);
	i_free_and_null(ctx->prev_inc_key);
	ctx->prev_inc_map = NULL;
}

static bool
sql_dict_maps_are_mergeable(struct sql_dict *dict,
			    const struct dict_sql_map *map1,
			    const struct dict_sql_map *map2,
			    const char *map1_key, const char *map2_key,
			    const ARRAY_TYPE(const_string) *map2_values)
{
	const struct dict_sql_map *map3;
	ARRAY_TYPE(const_string) map1_values;
	const char *const *v1, *const *v2;
	unsigned int i, count1, count2;

	if (strcmp(map1->table, map2->table) != 0)
		return FALSE;
	if (map1_key[0] != map2_key[0])
		return FALSE;
	if (map1_key[0] == DICT_PATH_PRIVATE[0]) {
		if (strcmp(map1->username_field, map2->username_field) != 0)
			return FALSE;
	}

	map3 = sql_dict_find_map(dict, map1_key, &map1_values);
	i_assert(map3 == map1);

	v1 = array_get(&map1_values, &count1);
	v2 = array_get(map2_values, &count2);
	if (count1 != count2)
		return FALSE;

	for (i = 0; i < count1; i++) {
		if (strcmp(v1[i], v2[i]) != 0)
			return FALSE;
	}
	return TRUE;
}

static void sql_dict_atomic_inc(struct dict_transaction_context *_ctx,
				const char *key, long long diff)
{
	struct sql_dict_transaction_context *ctx =
		(struct sql_dict_transaction_context *)_ctx;
	struct sql_dict *dict = (struct sql_dict *)_ctx->dict;
	const struct dict_sql_map *map;
	ARRAY_TYPE(const_string) values;

	map = sql_dict_find_map(dict, key, &values);
	if (map == NULL) {
		i_error("sql dict atomic inc: Invalid/unmapped key: %s", key);
		ctx->failed = TRUE;
		return;
	}

	if (ctx->prev_inc_map == NULL) {
		/* see if we can merge this increment SQL query with the
		   next one */
		ctx->prev_inc_map = map;
		ctx->prev_inc_key = i_strdup(key);
		ctx->prev_inc_diff = diff;
		return;
	}

	if (!sql_dict_maps_are_mergeable(dict, ctx->prev_inc_map, map,
					 ctx->prev_inc_key, key, &values)) {
		sql_dict_prev_inc_flush(ctx);
		sql_dict_atomic_inc_real(ctx, key, diff);
	} else T_BEGIN {
		struct dict_sql_build_query build;
		struct dict_sql_build_query_field *field;
		const char *query, *error;

		memset(&build, 0, sizeof(build));
		build.dict = dict;
		t_array_init(&build.fields, 1);
		build.extra_values = &values;
		build.key1 = key[0];
		build.inc = TRUE;

		field = array_append_space(&build.fields);
		field->map = ctx->prev_inc_map;
		field->value = t_strdup_printf("%lld", ctx->prev_inc_diff);
		field = array_append_space(&build.fields);
		field->map = map;
		field->value = t_strdup_printf("%lld", diff);

		if (sql_dict_update_query(&build, &query, &error) < 0) {
			i_error("dict-sql: Failed to increase %s: %s", key, error);
			ctx->failed = TRUE;
		} else {
			sql_update_get_rows(ctx->sql_ctx, query,
					    sql_dict_next_inc_row(ctx));
		}

		i_free_and_null(ctx->prev_inc_key);
		ctx->prev_inc_map = NULL;
	} T_END;
}

static struct dict sql_dict = {
	.name = "sql",

	{
		sql_dict_init,
		sql_dict_deinit,
		sql_dict_wait,
		sql_dict_lookup,
		sql_dict_iterate_init,
		sql_dict_iterate,
		sql_dict_iterate_deinit,
		sql_dict_transaction_init,
		sql_dict_transaction_commit,
		sql_dict_transaction_rollback,
		sql_dict_set,
		sql_dict_unset,
		sql_dict_append,
		sql_dict_atomic_inc,
		sql_dict_lookup_async
	}
};

static struct dict *dict_sql_drivers;

void dict_sql_register(void)
{
        const struct sql_db *const *drivers;
	unsigned int i, count;

	dict_sql_db_cache = sql_db_cache_init(DICT_SQL_MAX_UNUSED_CONNECTIONS);

	/* @UNSAFE */
	drivers = array_get(&sql_drivers, &count);
	dict_sql_drivers = i_new(struct dict, count + 1);

	for (i = 0; i < count; i++) {
		dict_sql_drivers[i] = sql_dict;
		dict_sql_drivers[i].name = drivers[i]->name;

		dict_driver_register(&dict_sql_drivers[i]);
	}
}

void dict_sql_unregister(void)
{
	int i;

	for (i = 0; dict_sql_drivers[i].name != NULL; i++)
		dict_driver_unregister(&dict_sql_drivers[i]);
	i_free(dict_sql_drivers);
	sql_db_cache_deinit(&dict_sql_db_cache);
	dict_sql_settings_deinit();
}
