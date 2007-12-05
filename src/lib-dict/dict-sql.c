/* Copyright (c) 2005-2007 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "istream.h"
#include "str.h"
#include "sql-api-private.h"
#include "sql-pool.h"
#include "dict-private.h"
#include "dict-sql.h"

#include <unistd.h>
#include <fcntl.h>

#define DICT_SQL_MAX_UNUSED_CONNECTIONS 10

struct sql_dict {
	struct dict dict;

	pool_t pool;
	struct sql_db *db;

	const char *connect_string, *username;
	const char *table, *select_field, *where_field, *username_field;
};

struct sql_dict_iterate_context {
	struct dict_iterate_context ctx;

	struct sql_result *result;
};

struct sql_dict_transaction_context {
	struct dict_transaction_context ctx;

	struct sql_transaction_context *sql_ctx;

	unsigned int failed:1;
	unsigned int changed:1;
};

static struct sql_pool *dict_sql_pool;

static void sql_dict_config_parse_line(struct sql_dict *dict, const char *line)
{
	const char *p, *value;

	while (*line == ' ') line++;
	value = strchr(line, '=');
	if (value == NULL)
		return;

	for (p = value; p[-1] == ' ' && p != line; p--) ;
	line = t_strdup_until(line, p);
	value++;
	while (*value == ' ') value++;

	if (strcmp(line, "connect") == 0)
		dict->connect_string = p_strdup(dict->pool, value);
	else if (strcmp(line, "table") == 0)
		dict->table = p_strdup(dict->pool, value);
	else if (strcmp(line, "select_field") == 0)
		dict->select_field = p_strdup(dict->pool, value);
	else if (strcmp(line, "where_field") == 0)
		dict->where_field = p_strdup(dict->pool, value);
	else if (strcmp(line, "username_field") == 0)
		dict->username_field = p_strdup(dict->pool, value);
}

static int sql_dict_read_config(struct sql_dict *dict, const char *path)
{
	struct istream *input;
	const char *line;
	int fd;

	fd = open(path, O_RDONLY);
	if (fd == -1) {
		i_error("open(%s) failed: %m", path);
		return -1;
	}

	input = i_stream_create_fd(fd, (size_t)-1, FALSE);
	while ((line = i_stream_read_next_line(input)) != NULL) {
		T_FRAME(
			sql_dict_config_parse_line(dict, line);
		);
	}
	i_stream_destroy(&input);
	(void)close(fd);

	if (dict->connect_string == NULL) {
		i_error("%s: 'connect' missing", path);
		return -1;
	}
	if (dict->table == NULL) {
		i_error("%s: 'table' missing", path);
		return -1;
	}
	if (dict->select_field == NULL) {
		i_error("%s: 'select_field' missing", path);
		return -1;
	}
	if (dict->where_field == NULL) {
		i_error("%s: 'where_field' missing", path);
		return -1;
	}
	if (dict->username_field == NULL) {
		i_error("%s: 'username_field' missing", path);
		return -1;
	}

	return 0;
}

static struct dict *
sql_dict_init(struct dict *driver, const char *uri,
	      enum dict_data_type value_type ATTR_UNUSED,
	      const char *username)
{
	struct sql_dict *dict;
	pool_t pool;

	pool = pool_alloconly_create("sql dict", 1024);
	dict = p_new(pool, struct sql_dict, 1);
	dict->pool = pool;
	dict->dict = *driver;
	dict->username = p_strdup(pool, username);

	if (sql_dict_read_config(dict, uri) < 0) {
		pool_unref(&pool);
		return NULL;
	}

	dict->db = sql_pool_new(dict_sql_pool, driver->name,
				dict->connect_string);
	return &dict->dict;
}

static void sql_dict_deinit(struct dict *_dict)
{
	struct sql_dict *dict = (struct sql_dict *)_dict;

	sql_deinit(&dict->db);
	pool_unref(&dict->pool);
}

static int sql_path_fix(const char **path, bool *private_r)
{
	const char *p;
	size_t len;

	p = strchr(*path, '/');
	if (p == NULL)
		return -1;
	len = p - *path;

	if (strncmp(*path, DICT_PATH_PRIVATE, len) == 0)
		*private_r = TRUE;
	else if (strncmp(*path, DICT_PATH_SHARED, len) == 0)
		*private_r = FALSE;
	else
		return -1;

	*path += len + 1;
	return 0;
}

static int sql_dict_lookup(struct dict *_dict, pool_t pool,
			   const char *key, const char **value_r)
{
	struct sql_dict *dict = (struct sql_dict *)_dict;
	struct sql_result *result;
	int ret;
	bool priv;

	if (sql_path_fix(&key, &priv) < 0) {
		*value_r = NULL;
		return -1;
	}

	T_FRAME(
		string_t *query = t_str_new(256);
		str_printfa(query, "SELECT %s FROM %s WHERE %s = '%s'",
			    dict->select_field, dict->table,
			    dict->where_field,
			    sql_escape_string(dict->db, key));
		if (priv) {
			str_printfa(query, " AND %s = '%s'",
				    dict->username_field,
				    sql_escape_string(dict->db, dict->username));
		}
		result = sql_query_s(dict->db, str_c(query));
	);

	ret = sql_result_next_row(result);
	if (ret <= 0)
		*value_r = NULL;
	else {
		*value_r =
			p_strdup(pool, sql_result_get_field_value(result, 0));
	}

	sql_result_free(result);
	return ret;
}

static struct dict_iterate_context *
sql_dict_iterate_init(struct dict *_dict, const char *path, 
		      enum dict_iterate_flags flags)
{
	struct sql_dict *dict = (struct sql_dict *)_dict;
        struct sql_dict_iterate_context *ctx;
	bool priv;

	ctx = i_new(struct sql_dict_iterate_context, 1);
	ctx->ctx.dict = _dict;

	if (sql_path_fix(&path, &priv) < 0) {
		ctx->result = NULL;
		return &ctx->ctx;
	}
	T_FRAME(
		string_t *query = t_str_new(256);
		str_printfa(query, "SELECT %s, %s FROM %s "
			    "WHERE %s LIKE '%s/%%'",
			    dict->where_field, dict->select_field,
			    dict->table, dict->where_field,
			    sql_escape_string(dict->db, path));
		if (priv) {
			str_printfa(query, " AND %s = '%s'",
				    dict->username_field,
				    sql_escape_string(dict->db,
						      dict->username));
		}
		if ((flags & DICT_ITERATE_FLAG_RECURSE) == 0) {
			str_printfa(query, " AND %s NOT LIKE '%s/%%/%%'",
				    dict->where_field,
				    sql_escape_string(dict->db, path));
		}
		if ((flags & DICT_ITERATE_FLAG_SORT_BY_KEY) != 0)
			str_printfa(query, " ORDER BY %s", dict->where_field);
		else if ((flags & DICT_ITERATE_FLAG_SORT_BY_VALUE) != 0)
			str_printfa(query, " ORDER BY %s", dict->select_field);
		ctx->result = sql_query_s(dict->db, str_c(query));
	);

	return &ctx->ctx;
}

static int sql_dict_iterate(struct dict_iterate_context *_ctx,
			    const char **key_r, const char **value_r)
{
	struct sql_dict_iterate_context *ctx =
		(struct sql_dict_iterate_context *)_ctx;
	int ret;

	if (ctx->result == NULL)
		return -1;

	if ((ret = sql_result_next_row(ctx->result)) <= 0)
		return ret;

	*key_r = sql_result_get_field_value(ctx->result, 0);
	*value_r = sql_result_get_field_value(ctx->result, 1);
	return 1;
}

static void sql_dict_iterate_deinit(struct dict_iterate_context *_ctx)
{
	struct sql_dict_iterate_context *ctx =
		(struct sql_dict_iterate_context *)_ctx;

	sql_result_free(ctx->result);
	i_free(ctx);
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

static int sql_dict_transaction_commit(struct dict_transaction_context *_ctx)
{
	struct sql_dict_transaction_context *ctx =
		(struct sql_dict_transaction_context *)_ctx;
	const char *error;
	int ret;

	if (ctx->failed) {
		sql_transaction_rollback(&ctx->sql_ctx);
		ret = -1;
	} else if (_ctx->changed) {
		ret = sql_transaction_commit_s(&ctx->sql_ctx, &error);
		if (ret < 0)
			i_error("sql dict: commit failed: %s", error);
	} else {
		/* nothing to be done */
		ret = 0;
	}
	i_free(ctx);
	return ret;
}

static void sql_dict_transaction_rollback(struct dict_transaction_context *_ctx)
{
	struct sql_dict_transaction_context *ctx =
		(struct sql_dict_transaction_context *)_ctx;

	if (_ctx->changed)
		sql_transaction_rollback(&ctx->sql_ctx);
	i_free(ctx);
}

static const char *
sql_dict_set_query(struct sql_dict *dict, const char *key, const char *value,
		   bool priv)
{
	if (priv) {
		return t_strdup_printf(
			"INSERT INTO %s (%s, %s, %s) VALUES ('%s', '%s', '%s') "
			"ON DUPLICATE KEY UPDATE %s = '%s'",
			dict->table, dict->select_field, dict->where_field,
			dict->username_field,
			sql_escape_string(dict->db, value),
			sql_escape_string(dict->db, key),
			sql_escape_string(dict->db, dict->username),
			dict->select_field,
			sql_escape_string(dict->db, value));
	} else {
		return t_strdup_printf(
			"INSERT INTO %s (%s, %s) VALUES ('%s', '%s') "
			"ON DUPLICATE KEY UPDATE %s = '%s'",
			dict->table, dict->select_field, dict->where_field,
			sql_escape_string(dict->db, value),
			sql_escape_string(dict->db, key),
                        dict->select_field,
			sql_escape_string(dict->db, value));
	}
}

static void sql_dict_set(struct dict_transaction_context *_ctx,
			 const char *key, const char *value)
{
	struct sql_dict_transaction_context *ctx =
		(struct sql_dict_transaction_context *)_ctx;
	struct sql_dict *dict = (struct sql_dict *)_ctx->dict;
	bool priv;

	if (sql_path_fix(&key, &priv) < 0) {
		i_error("sql dict: Invalid key: %s", key);
		ctx->failed = TRUE;
		return;
	}

	T_FRAME(
		const char *query;

		query = sql_dict_set_query(dict, key, value, priv);
		sql_update(ctx->sql_ctx, query);
	);
}

static const char *
sql_dict_unset_query(struct sql_dict *dict, const char *key, bool priv)
{
	if (priv) {
		return t_strdup_printf(
			"DELETE FROM %s WHERE %s = '%s' AND %s = '%s'",
			dict->table, dict->where_field,
			sql_escape_string(dict->db, key),
			dict->username_field,
			sql_escape_string(dict->db, dict->username));
	} else {
		return t_strdup_printf(
			"DELETE FROM %s WHERE %s = '%s'",
			dict->table, dict->where_field,
			sql_escape_string(dict->db, key));
	}
}

static void sql_dict_unset(struct dict_transaction_context *_ctx,
			   const char *key)
{
	struct sql_dict_transaction_context *ctx =
		(struct sql_dict_transaction_context *)_ctx;
	struct sql_dict *dict = (struct sql_dict *)_ctx->dict;
	bool priv;

	if (sql_path_fix(&key, &priv) < 0) {
		i_error("sql dict: Invalid key: %s", key);
		ctx->failed = TRUE;
		return;
	}

	T_FRAME(
		const char *query;

		query = sql_dict_unset_query(dict, key, priv);
		sql_update(ctx->sql_ctx, query);
	);
}

static const char *
sql_dict_atomic_inc_query(struct sql_dict *dict, const char *key,
			  long long diff, bool priv)
{
	if (priv) {
		return t_strdup_printf(
			"INSERT INTO %s (%s, %s, %s) VALUES (%lld, '%s', '%s') "
			"ON DUPLICATE KEY UPDATE %s = %s + %lld",
			dict->table, dict->select_field, dict->where_field,
			dict->username_field,
                        diff, sql_escape_string(dict->db, key),
			sql_escape_string(dict->db, dict->username),
                        dict->select_field, dict->select_field, diff);
	} else {
		return t_strdup_printf(
			"INSERT INTO %s (%s, %s) VALUES (%lld, '%s') "
			"ON DUPLICATE KEY UPDATE %s = %s + %lld",
			dict->table, dict->select_field, dict->where_field,
                        diff, sql_escape_string(dict->db, key),
                        dict->select_field, dict->select_field, diff);
	}
}

static void sql_dict_atomic_inc(struct dict_transaction_context *_ctx,
				const char *key, long long diff)
{
	struct sql_dict_transaction_context *ctx =
		(struct sql_dict_transaction_context *)_ctx;
	struct sql_dict *dict = (struct sql_dict *)_ctx->dict;
	bool priv;

	if (sql_path_fix(&key, &priv) < 0) {
		i_error("sql dict: Invalid key: %s", key);
		ctx->failed = TRUE;
		return;
	}

	T_FRAME(
		const char *query;

		query = sql_dict_atomic_inc_query(dict, key, diff, priv);
		sql_update(ctx->sql_ctx, query);
	);
}

static struct dict sql_dict = {
	MEMBER(name) "sql",

	{
		sql_dict_init,
		sql_dict_deinit,
		sql_dict_lookup,
		sql_dict_iterate_init,
		sql_dict_iterate,
		sql_dict_iterate_deinit,
		sql_dict_transaction_init,
		sql_dict_transaction_commit,
		sql_dict_transaction_rollback,
		sql_dict_set,
		sql_dict_unset,
		sql_dict_atomic_inc
	}
};

static struct dict *dict_sql_drivers;

void dict_sql_register(void)
{
        const struct sql_db *const *drivers;
	unsigned int i, count;

	dict_sql_pool = sql_pool_init(DICT_SQL_MAX_UNUSED_CONNECTIONS);

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
	sql_pool_deinit(&dict_sql_pool);
}
