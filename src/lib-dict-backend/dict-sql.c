/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "istream.h"
#include "hex-binary.h"
#include "hash.h"
#include "str.h"
#include "sql-api-private.h"
#include "sql-db-cache.h"
#include "dict-private.h"
#include "dict-sql-settings.h"
#include "dict-sql.h"
#include "dict-sql-private.h"

#include <unistd.h>
#include <fcntl.h>

#define DICT_SQL_MAX_UNUSED_CONNECTIONS 10

enum sql_recurse_type {
	SQL_DICT_RECURSE_NONE,
	SQL_DICT_RECURSE_ONE,
	SQL_DICT_RECURSE_FULL
};

struct sql_dict_param {
	enum dict_sql_type value_type;

	const char *value_str;
	int64_t value_int64;
	const void *value_binary;
	size_t value_binary_size;
};
ARRAY_DEFINE_TYPE(sql_dict_param, struct sql_dict_param);

struct sql_dict_iterate_context {
	struct dict_iterate_context ctx;
	pool_t pool;

	enum dict_iterate_flags flags;
	const char **paths;

	struct sql_result *result;
	string_t *key;
	const struct dict_sql_map *map;
	size_t key_prefix_len, pattern_prefix_len;
	unsigned int path_idx, sql_fields_start_idx, next_map_idx;
	bool synchronous_result;
	bool iter_query_sent;
	bool allow_null_map; /* allow next map to be NULL */
	const char *error;
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

	const struct dict_sql_map *prev_set_map;
	char *prev_set_key;
	char *prev_set_value;

	dict_transaction_commit_callback_t *async_callback;
	void *async_context;

	char *error;
};

static struct sql_db_cache *dict_sql_db_cache;

static void sql_dict_prev_inc_flush(struct sql_dict_transaction_context *ctx);
static void sql_dict_prev_set_flush(struct sql_dict_transaction_context *ctx);

static int
sql_dict_init(struct dict *driver, const char *uri,
	      const struct dict_settings *set,
	      struct dict **dict_r, const char **error_r)
{
	struct sql_settings sql_set;
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
	i_zero(&sql_set);
	sql_set.driver = driver->name;
	sql_set.connect_string = dict->set->connect;
	/* currently pgsql and sqlite don't support "ON DUPLICATE KEY" */
	dict->has_on_duplicate_key = strcmp(driver->name, "mysql") == 0;

	if (sql_db_cache_new(dict_sql_db_cache, &sql_set, &dict->db, error_r) < 0) {
		pool_unref(&pool);
		return -1;
	}

	if ((sql_get_flags(dict->db) & SQL_DB_FLAG_PREP_STATEMENTS) != 0) {
		hash_table_create(&dict->prep_stmt_hash, dict->pool,
				  0, str_hash, strcmp);
	}
	*dict_r = &dict->dict;
	return 0;
}

static void sql_dict_prep_stmt_hash_free(struct sql_dict *dict)
{
	struct hash_iterate_context *iter;
	struct sql_prepared_statement *prep_stmt;
	const char *query;

	if (!hash_table_is_created(dict->prep_stmt_hash))
		return;

	iter = hash_table_iterate_init(dict->prep_stmt_hash);
	while (hash_table_iterate(iter, dict->prep_stmt_hash, &query, &prep_stmt))
		sql_prepared_statement_deinit(&prep_stmt);
	hash_table_iterate_deinit(&iter);

	hash_table_destroy(&dict->prep_stmt_hash);
}

static void sql_dict_deinit(struct dict *_dict)
{
	struct sql_dict *dict = (struct sql_dict *)_dict;

	sql_dict_prep_stmt_hash_free(dict);
	sql_deinit(&dict->db);
	pool_unref(&dict->pool);
}

static void sql_dict_wait(struct dict *dict ATTR_UNUSED)
{
	/* FIXME: lib-sql doesn't support this yet */
}

static bool
dict_sql_map_match(const struct dict_sql_map *map, const char *path,
		   ARRAY_TYPE(const_string) *values, size_t *pat_len_r,
		   size_t *path_len_r, bool partial_ok, bool recurse)
{
	const char *path_start = path;
	const char *pat, *field, *p;
	size_t len;

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
	unsigned int i, count;
	size_t len;

	t_array_init(values, dict->set->max_field_count);
	maps = array_get(&dict->set->maps, &count);
	for (i = 0; i < count; i++) {
		if (dict_sql_map_match(&maps[i], path, values,
				       &len, &len, FALSE, FALSE))
			return &maps[i];
	}
	return NULL;
}

static void
sql_dict_statement_bind(struct sql_statement *stmt, unsigned int column_idx,
			const struct sql_dict_param *param)
{
	switch (param->value_type) {
	case DICT_SQL_TYPE_STRING:
		sql_statement_bind_str(stmt, column_idx, param->value_str);
		break;
	case DICT_SQL_TYPE_INT:
	case DICT_SQL_TYPE_UINT:
		sql_statement_bind_int64(stmt, column_idx, param->value_int64);
		break;
	case DICT_SQL_TYPE_HEXBLOB:
		sql_statement_bind_binary(stmt, column_idx, param->value_binary,
					  param->value_binary_size);
		break;
	}
}

static struct sql_statement *
sql_dict_statement_init(struct sql_dict *dict, const char *query,
			const ARRAY_TYPE(sql_dict_param) *params)
{
	struct sql_statement *stmt;
	struct sql_prepared_statement *prep_stmt;
	const struct sql_dict_param *param;

	if (hash_table_is_created(dict->prep_stmt_hash)) {
		prep_stmt = hash_table_lookup(dict->prep_stmt_hash, query);
		if (prep_stmt == NULL) {
			const char *query_dup = p_strdup(dict->pool, query);
			prep_stmt = sql_prepared_statement_init(dict->db, query);
			hash_table_insert(dict->prep_stmt_hash, query_dup, prep_stmt);
		}
		stmt = sql_statement_init_prepared(prep_stmt);
	} else {
		/* Prepared statements not supported by the backend.
		   Just use regular statements to avoid wasting memory. */
		stmt = sql_statement_init(dict->db, query);
	}

	array_foreach(params, param) {
		sql_dict_statement_bind(stmt, array_foreach_idx(params, param),
					param);
	}
	return stmt;
}

static int
sql_dict_value_get(const struct dict_sql_map *map,
		   enum dict_sql_type value_type, const char *field_name,
		   const char *value, const char *value_suffix,
		   ARRAY_TYPE(sql_dict_param) *params, const char **error_r)
{
	struct sql_dict_param *param;
	buffer_t *buf;

	param = array_append_space(params);
	param->value_type = value_type;

	switch (value_type) {
	case DICT_SQL_TYPE_STRING:
		if (value_suffix[0] != '\0')
			value = t_strconcat(value, value_suffix, NULL);
		param->value_str = value;
		return 0;
	case DICT_SQL_TYPE_INT:
		if (value_suffix[0] != '\0' ||
		    str_to_int64(value, &param->value_int64) < 0) {
			*error_r = t_strdup_printf(
				"%s field's value isn't 64bit signed integer: %s%s (in pattern: %s)",
				field_name, value, value_suffix, map->pattern);
			return -1;
		}
		return 0;
	case DICT_SQL_TYPE_UINT:
		if (value_suffix[0] != '\0' || value[0] == '-' ||
		    str_to_int64(value, &param->value_int64) < 0) {
			*error_r = t_strdup_printf(
				"%s field's value isn't 64bit unsigned integer: %s%s (in pattern: %s)",
				field_name, value, value_suffix, map->pattern);
			return -1;
		}
		return 0;
	case DICT_SQL_TYPE_HEXBLOB:
		break;
	}

	buf = t_buffer_create(strlen(value)/2);
	if (hex_to_binary(value, buf) < 0) {
		/* we shouldn't get untrusted input here. it's also a bit
		   annoying to handle this error. */
		*error_r = t_strdup_printf("%s field's value isn't hexblob: %s (in pattern: %s)",
					   field_name, value, map->pattern);
		return -1;
	}
	str_append(buf, value_suffix);
	param->value_binary = buf->data;
	param->value_binary_size = buf->used;
	return 0;
}

static int
sql_dict_field_get_value(const struct dict_sql_map *map,
			 const struct dict_sql_field *field,
			 const char *value, const char *value_suffix,
			 ARRAY_TYPE(sql_dict_param) *params,
			 const char **error_r)
{
	return sql_dict_value_get(map, field->value_type, field->name,
				  value, value_suffix, params, error_r);
}

static int
sql_dict_where_build(struct sql_dict *dict, const struct dict_sql_map *map,
		     const ARRAY_TYPE(const_string) *values_arr,
		     char key1, enum sql_recurse_type recurse_type,
		     string_t *query, ARRAY_TYPE(sql_dict_param) *params,
		     const char **error_r)
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
		str_printfa(query, " %s = ?", sql_fields[i].name);
		if (sql_dict_field_get_value(map, &sql_fields[i], values[i], "",
					     params, error_r) < 0)
			return -1;
	}
	switch (recurse_type) {
	case SQL_DICT_RECURSE_NONE:
		break;
	case SQL_DICT_RECURSE_ONE:
		if (i > 0)
			str_append(query, " AND");
		if (i < count2) {
			str_printfa(query, " %s LIKE ?", sql_fields[i].name);
			if (sql_dict_field_get_value(map, &sql_fields[i],
						     values[i], "/%",
						     params, error_r) < 0)
				return -1;
			str_printfa(query, " AND %s NOT LIKE ?", sql_fields[i].name);
			if (sql_dict_field_get_value(map, &sql_fields[i],
						     values[i], "/%/%",
						     params, error_r) < 0)
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
			if (sql_dict_field_get_value(map, &sql_fields[i],
						     values[i], "/%",
						     params, error_r) < 0)
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
		     const struct dict_sql_map **map_r,
		     struct sql_statement **stmt_r,
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

	string_t *query = t_str_new(256);
	ARRAY_TYPE(sql_dict_param) params;
	t_array_init(&params, 4);
	str_printfa(query, "SELECT %s FROM %s",
		    map->value_field, map->table);
	if (sql_dict_where_build(dict, map, &values, key[0],
				 SQL_DICT_RECURSE_NONE, query,
				 &params, &error) < 0) {
		*error_r = t_strdup_printf(
			"sql dict lookup: Failed to lookup key %s: %s", key, error);
		return -1;
	}
	*stmt_r = sql_dict_statement_init(dict, str_c(query), &params);
	return 0;
}

static const char *
sql_dict_result_unescape(enum dict_sql_type type, pool_t pool,
			 struct sql_result *result, unsigned int result_idx)
{
	const unsigned char *data;
	size_t size;
	const char *value;
	string_t *str;

	switch (type) {
	case DICT_SQL_TYPE_STRING:
	case DICT_SQL_TYPE_INT:
	case DICT_SQL_TYPE_UINT:
		value = sql_result_get_field_value(result, result_idx);
		return value == NULL ? "" : p_strdup(pool, value);
	case DICT_SQL_TYPE_HEXBLOB:
		break;
	}

	data = sql_result_get_field_value_binary(result, result_idx, &size);
	str = str_new(pool, size*2 + 1);
	binary_to_hex_append(str, data, size);
	return str_c(str);
}

static const char *
sql_dict_result_unescape_value(const struct dict_sql_map *map, pool_t pool,
			       struct sql_result *result)
{
	return sql_dict_result_unescape(map->value_types[0], pool, result, 0);
}

static const char *const *
sql_dict_result_unescape_values(const struct dict_sql_map *map, pool_t pool,
				struct sql_result *result)
{
	const char **values;
	unsigned int i;

	values = p_new(pool, const char *, map->values_count + 1);
	for (i = 0; i < map->values_count; i++) {
		values[i] = sql_dict_result_unescape(map->value_types[i],
						     pool, result, i);
	}
	return values;
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

static int sql_dict_lookup(struct dict *_dict, pool_t pool, const char *key,
			   const char **value_r, const char **error_r)
{
	struct sql_dict *dict = (struct sql_dict *)_dict;
	const struct dict_sql_map *map;
	struct sql_statement *stmt;
	struct sql_result *result = NULL;
	int ret;

	*value_r = NULL;

	if (sql_lookup_get_query(dict, key, &map, &stmt, error_r) < 0)
		return -1;

	result = sql_statement_query_s(&stmt);
	ret = sql_result_next_row(result);
	if (ret < 0) {
		*error_r = t_strdup_printf("dict sql lookup failed: %s",
					   sql_result_get_error(result));
	} else if (ret > 0) {
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

	i_zero(&result);
	result.ret = sql_result_next_row(sql_result);
	if (result.ret < 0)
		result.error = sql_result_get_error(sql_result);
	else if (result.ret > 0) {
		result.values = sql_dict_result_unescape_values(ctx->map,
			pool_datastack_create(), sql_result);
		result.value = result.values[0];
		if (result.value == NULL) {
			/* NULL value returned. we'll treat this as
			   "not found", which is probably what is usually
			   wanted. */
			result.ret = 0;
		}
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
	struct sql_statement *stmt;
	const char *error;

	if (sql_lookup_get_query(dict, key, &map, &stmt, &error) < 0) {
		struct dict_lookup_result result;

		i_zero(&result);
		result.ret = -1;
		result.error = error;
		callback(&result, context);
	} else {
		ctx = i_new(struct sql_dict_lookup_context, 1);
		ctx->callback = callback;
		ctx->context = context;
		ctx->map = map;
		sql_statement_query(&stmt, sql_dict_lookup_async_callback, ctx);
	}
}

static const struct dict_sql_map *
sql_dict_iterate_find_next_map(struct sql_dict_iterate_context *ctx,
			       ARRAY_TYPE(const_string) *values)
{
	struct sql_dict *dict = (struct sql_dict *)ctx->ctx.dict;
	const struct dict_sql_map *maps;
	unsigned int i, count;
	size_t pat_len, path_len;
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
				  struct sql_statement **stmt_r,
				  const char **error_r)
{
	struct sql_dict *dict = (struct sql_dict *)ctx->ctx.dict;
	const struct dict_sql_map *map;
	ARRAY_TYPE(const_string) values;
	const struct dict_sql_field *sql_fields;
	enum sql_recurse_type recurse_type;
	unsigned int i, count;

	map = sql_dict_iterate_find_next_map(ctx, &values);
	/* NULL map is allowed if we have already done some lookups */
	if (map == NULL) {
		if (!ctx->allow_null_map) {
			*error_r = "Invalid/unmapped path";
			return -1;
		}
		return 0;
	}

	if (ctx->result != NULL) {
		sql_result_unref(ctx->result);
		ctx->result = NULL;
	}

	string_t *query = t_str_new(256);
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

	ARRAY_TYPE(sql_dict_param) params;
	t_array_init(&params, 4);
	if (sql_dict_where_build(dict, map, &values,
				 ctx->paths[ctx->path_idx][0],
				 recurse_type, query, &params, error_r) < 0)
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

	if (ctx->ctx.max_rows > 0) {
		i_assert(ctx->ctx.row_count < ctx->ctx.max_rows);
		str_printfa(query, " LIMIT %"PRIu64,
			    ctx->ctx.max_rows - ctx->ctx.row_count);
	}

	*stmt_r = sql_dict_statement_init(dict, str_c(query), &params);
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

static int sql_dict_iterate_next_query(struct sql_dict_iterate_context *ctx)
{
	struct sql_statement *stmt;
	const char *error;
	unsigned int path_idx = ctx->path_idx;
	int ret;

	ret = sql_dict_iterate_build_next_query(ctx, &stmt, &error);
	if (ret <= 0) {
		/* this is expected error */
		if (ret == 0)
			return ret;
		/* failed */
		ctx->error = p_strdup_printf(ctx->pool,
			"sql dict iterate failed for %s: %s",
			ctx->paths[path_idx], error);
		return -1;
	}

	if ((ctx->flags & DICT_ITERATE_FLAG_ASYNC) == 0) {
		ctx->result = sql_statement_query_s(&stmt);
	} else {
		i_assert(ctx->result == NULL);
		ctx->synchronous_result = TRUE;
		sql_statement_query(&stmt, sql_dict_iterate_callback, ctx);
		ctx->synchronous_result = FALSE;
	}
	return ret;
}

static struct dict_iterate_context *
sql_dict_iterate_init(struct dict *_dict, const char *const *paths,
		      enum dict_iterate_flags flags)
{
	struct sql_dict_iterate_context *ctx;
	unsigned int i, path_count;
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
	return &ctx->ctx;
}

static bool sql_dict_iterate(struct dict_iterate_context *_ctx,
			     const char **key_r, const char **value_r)
{
	struct sql_dict_iterate_context *ctx =
		(struct sql_dict_iterate_context *)_ctx;
	const char *p, *value;
	unsigned int i, sql_field_i, count;
	int ret;

	_ctx->has_more = FALSE;
	if (ctx->error != NULL)
		return FALSE;
	if (!ctx->iter_query_sent) {
		ctx->iter_query_sent = TRUE;
		if (sql_dict_iterate_next_query(ctx) <= 0)
			return FALSE;
	}

	if (ctx->result == NULL) {
		/* wait for async lookup to finish */
		i_assert((ctx->flags & DICT_ITERATE_FLAG_ASYNC) != 0);
		_ctx->has_more = TRUE;
		return FALSE;
	}

	ret = sql_result_next_row(ctx->result);
	while (ret == SQL_RESULT_NEXT_MORE) {
		if ((ctx->flags & DICT_ITERATE_FLAG_ASYNC) == 0)
			sql_result_more_s(&ctx->result);
		else {
			/* get more results asynchronously */
			ctx->synchronous_result = TRUE;
			sql_result_more(&ctx->result, sql_dict_iterate_callback, ctx);
			ctx->synchronous_result = FALSE;
			if (ctx->result == NULL) {
				_ctx->has_more = TRUE;
				return FALSE;
			}
		}
		ret = sql_result_next_row(ctx->result);
	}
	if (ret == 0) {
		/* see if there are more results in the next map.
		   don't do it if we're looking for an exact match, since we
		   already should have handled it. */
		if ((ctx->flags & DICT_ITERATE_FLAG_EXACT_KEY) != 0)
			return FALSE;
		ctx->iter_query_sent = FALSE;
		/* we have gotten *SOME* results, so can allow
		   unmapped next key now. */
		ctx->allow_null_map = TRUE;
		return sql_dict_iterate(_ctx, key_r, value_r);
	}
	if (ret < 0) {
		ctx->error = p_strdup_printf(ctx->pool,
			"dict sql iterate failed: %s",
			sql_result_get_error(ctx->result));
		return FALSE;
	}

	/* convert fetched row to dict key */
	str_truncate(ctx->key, ctx->key_prefix_len);
	if (ctx->key_prefix_len > 0 &&
	    str_c(ctx->key)[ctx->key_prefix_len-1] != '/')
		str_append_c(ctx->key, '/');

	count = sql_result_get_fields_count(ctx->result);
	i = (ctx->flags & DICT_ITERATE_FLAG_NO_VALUE) != 0 ? 0 :
		ctx->map->values_count;
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

static int sql_dict_iterate_deinit(struct dict_iterate_context *_ctx,
				   const char **error_r)
{
	struct sql_dict_iterate_context *ctx =
		(struct sql_dict_iterate_context *)_ctx;
	int ret = ctx->error != NULL ? -1 : 0;

	*error_r = t_strdup(ctx->error);
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
	pool_unref(&ctx->inc_row_pool);
	i_free(ctx->prev_inc_key);
	i_free(ctx->error);
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
sql_dict_transaction_commit_callback(const struct sql_commit_result *sql_result,
				     struct sql_dict_transaction_context *ctx)
{
	struct dict_commit_result result;

	i_zero(&result);
	if (sql_result->error == NULL)
		result.ret = sql_dict_transaction_has_nonexistent(ctx) ?
			DICT_COMMIT_RET_NOTFOUND : DICT_COMMIT_RET_OK;
	else {
		result.error = t_strdup_printf("sql dict: commit failed: %s",
					       sql_result->error);
		switch (sql_result->error_type) {
		case SQL_RESULT_ERROR_TYPE_UNKNOWN:
		default:
			result.ret = DICT_COMMIT_RET_FAILED;
			break;
		case SQL_RESULT_ERROR_TYPE_WRITE_UNCERTAIN:
			result.ret = DICT_COMMIT_RET_WRITE_UNCERTAIN;
			break;
		}
	}

	if (ctx->async_callback != NULL)
		ctx->async_callback(&result, ctx->async_context);
	else if (result.ret < 0)
		i_error("%s", result.error);
	sql_dict_transaction_free(ctx);
}

static void
sql_dict_transaction_commit(struct dict_transaction_context *_ctx, bool async,
			    dict_transaction_commit_callback_t *callback,
			    void *context)
{
	struct sql_dict_transaction_context *ctx =
		(struct sql_dict_transaction_context *)_ctx;
	const char *error;
	struct dict_commit_result result;

	if (ctx->prev_inc_map != NULL)
		sql_dict_prev_inc_flush(ctx);
	if (ctx->prev_set_map != NULL)
		sql_dict_prev_set_flush(ctx);

	/* note that the above calls might still set ctx->error */
	i_zero(&result);
	result.ret = DICT_COMMIT_RET_FAILED;
	result.error = t_strdup(ctx->error);

	if (ctx->error != NULL) {
		sql_transaction_rollback(&ctx->sql_ctx);
	} else if (!_ctx->changed) {
		/* nothing changed, no need to commit */
		sql_transaction_rollback(&ctx->sql_ctx);
		result.ret = DICT_COMMIT_RET_OK;
	} else if (async) {
		ctx->async_callback = callback;
		ctx->async_context = context;
		sql_transaction_commit(&ctx->sql_ctx,
			sql_dict_transaction_commit_callback, ctx);
		return;
	} else if (sql_transaction_commit_s(&ctx->sql_ctx, &error) < 0) {
		result.error = t_strdup_printf(
			"sql dict: commit failed: %s", error);
	} else {
		if (sql_dict_transaction_has_nonexistent(ctx))
			result.ret = DICT_COMMIT_RET_NOTFOUND;
		else
			result.ret = DICT_COMMIT_RET_OK;
	}
	sql_dict_transaction_free(ctx);

	callback(&result, context);
}

static void sql_dict_transaction_rollback(struct dict_transaction_context *_ctx)
{
	struct sql_dict_transaction_context *ctx =
		(struct sql_dict_transaction_context *)_ctx;

	sql_transaction_rollback(&ctx->sql_ctx);
	sql_dict_transaction_free(ctx);
}

static struct sql_statement *
sql_dict_transaction_stmt_init(struct sql_dict_transaction_context *ctx,
			       const char *query,
			       const ARRAY_TYPE(sql_dict_param) *params)
{
	struct sql_dict *dict = (struct sql_dict *)ctx->ctx.dict;
	struct sql_statement *stmt =
		sql_dict_statement_init(dict, query, params);

	if (ctx->ctx.timestamp.tv_sec != 0)
		sql_statement_set_timestamp(stmt, &ctx->ctx.timestamp);
	return stmt;
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
};

static int sql_dict_set_query(struct sql_dict_transaction_context *ctx,
			      const struct dict_sql_build_query *build,
			      struct sql_statement **stmt_r,
			      const char **error_r)
{
	struct sql_dict *dict = build->dict;
	const struct dict_sql_build_query_field *fields;
	const struct dict_sql_field *sql_fields;
	ARRAY_TYPE(sql_dict_param) params;
	const char *const *extra_values;
	unsigned int i, field_count, count, count2;
	string_t *prefix, *suffix;

	fields = array_get(&build->fields, &field_count);
	i_assert(field_count > 0);

	t_array_init(&params, 4);
	prefix = t_str_new(64);
	suffix = t_str_new(256);
	str_printfa(prefix, "INSERT INTO %s", fields[0].map->table);
	str_append(prefix, " (");
	str_append(suffix, ") VALUES (");
	for (i = 0; i < field_count; i++) {
		if (i > 0) {
			str_append_c(prefix, ',');
			str_append_c(suffix, ',');
		}
		str_append(prefix, t_strcut(fields[i].map->value_field, ','));

		enum dict_sql_type value_type =
			fields[i].map->value_types[0];
		str_append_c(suffix, '?');
		if (sql_dict_value_get(fields[i].map,
				       value_type, "value", fields[i].value,
				       "", &params, error_r) < 0)
			return -1;
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
		str_append(suffix, ",?");
		if (sql_dict_field_get_value(fields[0].map, &sql_fields[i],
					     extra_values[i], "",
					     &params, error_r) < 0)
			return -1;
	}

	str_append_str(prefix, suffix);
	str_append_c(prefix, ')');
	if (!dict->has_on_duplicate_key) {
		*stmt_r = sql_dict_transaction_stmt_init(ctx, str_c(prefix), &params);
		return 0;
	}

	str_append(prefix, " ON DUPLICATE KEY UPDATE ");
	for (i = 0; i < field_count; i++) {
		const char *first_value_field =
			t_strcut(fields[i].map->value_field, ',');
		if (i > 0)
			str_append_c(prefix, ',');
		str_append(prefix, first_value_field);
		str_append_c(prefix, '=');

		enum dict_sql_type value_type =
			fields[i].map->value_types[0];
		str_append_c(prefix, '?');
		if (sql_dict_value_get(fields[i].map,
				       value_type, "value", fields[i].value,
				       "", &params, error_r) < 0)
			return -1;
	}
	*stmt_r = sql_dict_transaction_stmt_init(ctx, str_c(prefix), &params);
	return 0;
}

static int
sql_dict_update_query(const struct dict_sql_build_query *build,
		      const char **query_r, ARRAY_TYPE(sql_dict_param) *params,
		      const char **error_r)
{
	struct sql_dict *dict = build->dict;
	const struct dict_sql_build_query_field *fields;
	unsigned int i, field_count;
	string_t *query;

	fields = array_get(&build->fields, &field_count);
	i_assert(field_count > 0);

	query = t_str_new(64);
	str_printfa(query, "UPDATE %s SET ", fields[0].map->table);
	for (i = 0; i < field_count; i++) {
		const char *first_value_field =
			t_strcut(fields[i].map->value_field, ',');
		if (i > 0)
			str_append_c(query, ',');
		str_printfa(query, "%s=%s+?", first_value_field,
			    first_value_field);
	}

	if (sql_dict_where_build(dict, fields[0].map, build->extra_values,
				 build->key1, SQL_DICT_RECURSE_NONE, query,
				 params, error_r) < 0)
		return -1;
	*query_r = str_c(query);
	return 0;
}

static void sql_dict_set_real(struct dict_transaction_context *_ctx,
			      const char *key, const char *value)
{
	struct sql_dict_transaction_context *ctx =
		(struct sql_dict_transaction_context *)_ctx;
	struct sql_dict *dict = (struct sql_dict *)_ctx->dict;
	const struct dict_sql_map *map;
	struct sql_statement *stmt;
	ARRAY_TYPE(const_string) values;
	struct dict_sql_build_query build;
	struct dict_sql_build_query_field field;
	const char *error;

	if (ctx->error != NULL)
		return;

	map = sql_dict_find_map(dict, key, &values);
	if (map == NULL) {
		ctx->error = i_strdup_printf(
			"dict-sql: Invalid/unmapped key: %s", key);
		return;
	}

	field.map = map;
	field.value = value;

	i_zero(&build);
	build.dict = dict;
	t_array_init(&build.fields, 1);
	array_append(&build.fields, &field, 1);
	build.extra_values = &values;
	build.key1 = key[0];

	if (sql_dict_set_query(ctx, &build, &stmt, &error) < 0) {
		ctx->error = i_strdup_printf("dict-sql: Failed to set %s=%s: %s",
					     key, value, error);
	} else {
		sql_update_stmt(ctx->sql_ctx, &stmt);
	}
}

static void sql_dict_unset(struct dict_transaction_context *_ctx,
			   const char *key)
{
	struct sql_dict_transaction_context *ctx =
		(struct sql_dict_transaction_context *)_ctx;
	struct sql_dict *dict = (struct sql_dict *)_ctx->dict;
	const struct dict_sql_map *map;
	ARRAY_TYPE(const_string) values;
	string_t *query = t_str_new(256);
	ARRAY_TYPE(sql_dict_param) params;
	const char *error;

	if (ctx->error != NULL)
		return;

	if (ctx->prev_inc_map != NULL)
		sql_dict_prev_inc_flush(ctx);
	if (ctx->prev_set_map != NULL)
		sql_dict_prev_set_flush(ctx);

	map = sql_dict_find_map(dict, key, &values);
	if (map == NULL) {
		ctx->error = i_strdup_printf("dict-sql: Invalid/unmapped key: %s", key);
		return;
	}

	str_printfa(query, "DELETE FROM %s", map->table);
	t_array_init(&params, 4);
	if (sql_dict_where_build(dict, map, &values, key[0],
				 SQL_DICT_RECURSE_NONE, query,
				 &params, &error) < 0) {
		ctx->error = i_strdup_printf(
			"dict-sql: Failed to delete %s: %s", key, error);
	} else {
		struct sql_statement *stmt =
			sql_dict_transaction_stmt_init(ctx, str_c(query), &params);
		sql_update_stmt(ctx->sql_ctx, &stmt);
	}
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
	struct dict_sql_build_query build;
	struct dict_sql_build_query_field field;
	ARRAY_TYPE(sql_dict_param) params;
	struct sql_dict_param *param;
	const char *query, *error;

	if (ctx->error != NULL)
		return;

	map = sql_dict_find_map(dict, key, &values);
	i_assert(map != NULL);

	field.map = map;
	field.value = NULL; /* unused */

	i_zero(&build);
	build.dict = dict;
	t_array_init(&build.fields, 1);
	array_append(&build.fields, &field, 1);
	build.extra_values = &values;
	build.key1 = key[0];

	t_array_init(&params, 4);
	param = array_append_space(&params);
	param->value_type = DICT_SQL_TYPE_INT;
	param->value_int64 = diff;

	if (sql_dict_update_query(&build, &query, &params, &error) < 0) {
		ctx->error = i_strdup_printf(
			"dict-sql: Failed to increase %s: %s", key, error);
	} else {
		struct sql_statement *stmt =
			sql_dict_transaction_stmt_init(ctx, query, &params);
		sql_update_stmt_get_rows(ctx->sql_ctx, &stmt,
					 sql_dict_next_inc_row(ctx));
	}
}

static void sql_dict_prev_set_flush(struct sql_dict_transaction_context *ctx)
{
	sql_dict_set_real(&ctx->ctx, ctx->prev_set_key, ctx->prev_set_value);
	i_free_and_null(ctx->prev_set_value);
	i_free_and_null(ctx->prev_set_key);
	ctx->prev_set_map = NULL;
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

static void sql_dict_set(struct dict_transaction_context *_ctx,
			 const char *key, const char *value)
{
	struct sql_dict_transaction_context *ctx =
		(struct sql_dict_transaction_context *)_ctx;
	struct sql_dict *dict = (struct sql_dict *)_ctx->dict;
	const struct dict_sql_map *map;
	ARRAY_TYPE(const_string) values;

	if (ctx->error != NULL)
		return;

	if (ctx->prev_inc_map != NULL)
		sql_dict_prev_inc_flush(ctx);

	map = sql_dict_find_map(dict, key, &values);
	if (map == NULL) {
		ctx->error = i_strdup_printf(
			"sql dict set: Invalid/unmapped key: %s", key);
		return;
	}

	if (ctx->prev_set_map == NULL) {
		/* see if we can merge this increment SQL query with the
		   next one */
		ctx->prev_set_map = map;
		ctx->prev_set_key = i_strdup(key);
		ctx->prev_set_value = i_strdup(value);
		return;
	}

	if (!sql_dict_maps_are_mergeable(dict, ctx->prev_set_map, map,
					 ctx->prev_set_key, key, &values)) {
		sql_dict_prev_set_flush(ctx);
		sql_dict_set_real(&ctx->ctx, key, value);
	} else {
		struct dict_sql_build_query build;
		struct dict_sql_build_query_field *field;
		struct sql_statement *stmt;
		const char *error;

		i_zero(&build);
		build.dict = dict;
		t_array_init(&build.fields, 1);
		build.extra_values = &values;
		build.key1 = key[0];

		field = array_append_space(&build.fields);
		field->map = ctx->prev_set_map;
		field->value = ctx->prev_set_value;
		field = array_append_space(&build.fields);
		field->map = map;
		field->value = value;

		if (sql_dict_set_query(ctx, &build, &stmt, &error) < 0) {
			ctx->error = i_strdup_printf(
				"dict-sql: Failed to set %s: %s", key, error);
		} else {
			sql_update_stmt(ctx->sql_ctx, &stmt);
		}
		i_free_and_null(ctx->prev_set_value);
		i_free_and_null(ctx->prev_set_key);
		ctx->prev_set_map = NULL;
	}
}

static void sql_dict_atomic_inc(struct dict_transaction_context *_ctx,
				const char *key, long long diff)
{
	struct sql_dict_transaction_context *ctx =
		(struct sql_dict_transaction_context *)_ctx;
	struct sql_dict *dict = (struct sql_dict *)_ctx->dict;
	const struct dict_sql_map *map;
	ARRAY_TYPE(const_string) values;

	if (ctx->error != NULL)
		return;

	if (ctx->prev_set_map != NULL)
		sql_dict_prev_set_flush(ctx);

	map = sql_dict_find_map(dict, key, &values);
	if (map == NULL) {
		ctx->error = i_strdup_printf(
			"sql dict atomic inc: Invalid/unmapped key: %s", key);
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
	} else {
		struct dict_sql_build_query build;
		struct dict_sql_build_query_field *field;
		ARRAY_TYPE(sql_dict_param) params;
		struct sql_dict_param *param;
		const char *query, *error;

		i_zero(&build);
		build.dict = dict;
		t_array_init(&build.fields, 1);
		build.extra_values = &values;
		build.key1 = key[0];

		field = array_append_space(&build.fields);
		field->map = ctx->prev_inc_map;
		field = array_append_space(&build.fields);
		field->map = map;
		/* field->value is unused */

		t_array_init(&params, 4);
		param = array_append_space(&params);
		param->value_type = DICT_SQL_TYPE_INT;
		param->value_int64 = ctx->prev_inc_diff;

		param = array_append_space(&params);
		param->value_type = DICT_SQL_TYPE_INT;
		param->value_int64 = diff;

		if (sql_dict_update_query(&build, &query, &params, &error) < 0) {
			ctx->error = i_strdup_printf(
				"dict-sql: Failed to increase %s: %s", key, error);
		} else {
			struct sql_statement *stmt =
				sql_dict_transaction_stmt_init(ctx, query, &params);
			sql_update_stmt_get_rows(ctx->sql_ctx, &stmt,
						 sql_dict_next_inc_row(ctx));
		}

		i_free_and_null(ctx->prev_inc_key);
		ctx->prev_inc_map = NULL;
	}
}

static struct dict sql_dict = {
	.name = "sql",

	{
		.init = sql_dict_init,
		.deinit = sql_dict_deinit,
		.wait = sql_dict_wait,
		.lookup = sql_dict_lookup,
		.iterate_init = sql_dict_iterate_init,
		.iterate = sql_dict_iterate,
		.iterate_deinit = sql_dict_iterate_deinit,
		.transaction_init = sql_dict_transaction_init,
		.transaction_commit = sql_dict_transaction_commit,
		.transaction_rollback = sql_dict_transaction_rollback,
		.set = sql_dict_set,
		.unset = sql_dict_unset,
		.atomic_inc = sql_dict_atomic_inc,
		.lookup_async = sql_dict_lookup_async,
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
