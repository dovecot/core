/* Copyright (C) 2005 Timo Sirainen */

#include "lib.h"
#include "array.h"
#include "istream.h"
#include "str.h"
#include "strescape.h"
#include "sql-api-private.h"
#include "dict-private.h"
#include "dict-sql.h"

#include <unistd.h>
#include <fcntl.h>

struct sql_dict {
	struct dict dict;

	pool_t pool;
	struct sql_db *db;

	const char *connect_string;
	const char *table, *select_field, *where_field;
};

struct sql_dict_iterate_context {
	struct dict_iterate_context ctx;

	struct sql_result *result;
};

struct sql_dict_transaction_context {
	struct dict_transaction_context ctx;

	struct sql_transaction_context *sql_ctx;
};

static int sql_dict_read_config(struct sql_dict *dict, const char *path)
{
	struct istream *input;
	const char *line, *value, *p;
	int fd;

	fd = open(path, O_RDONLY);
	if (fd == -1) {
		i_error("open(%s) failed: %m", path);
		return -1;
	}

	input = i_stream_create_file(fd, default_pool, (size_t)-1, FALSE);
	while ((line = i_stream_read_next_line(input)) != NULL) {
		while (*line == ' ') line++;
		value = strchr(line, '=');
		if (value == NULL)
			continue;

		t_push();
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

		t_pop();
	}
	i_stream_unref(&input);
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

	return 0;
}

static struct dict *sql_dict_init(struct dict *dict_class, const char *uri)
{
	struct sql_dict *dict;
	pool_t pool;

	pool = pool_alloconly_create("sql dict", 1024);
	dict = p_new(pool, struct sql_dict, 1);
	dict->pool = pool;
	dict->dict = *dict_class;

	if (sql_dict_read_config(dict, uri) < 0) {
		pool_unref(pool);
		return NULL;
	}

	t_push();
	dict->db = sql_init(dict_class->name, dict->connect_string);
	t_pop();
	return &dict->dict;
}

static void sql_dict_deinit(struct dict *_dict)
{
	struct sql_dict *dict = (struct sql_dict *)_dict;

	sql_deinit(&dict->db);
	pool_unref(dict->pool);
}

static int sql_dict_lookup(struct dict *_dict, pool_t pool,
			   const char *key, const char **value_r)
{
	struct sql_dict *dict = (struct sql_dict *)_dict;
	struct sql_result *result;
	const char *query;
	int ret;

	t_push();
	query = t_strdup_printf("SELECT %s FROM %s WHERE %s = '%s'",
				dict->select_field, dict->table,
				dict->where_field, str_escape(key));
	result = sql_query_s(dict->db, query);
	t_pop();

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
sql_dict_iterate_init(struct dict *_dict, const char *path, bool recurse)
{
	struct sql_dict *dict = (struct sql_dict *)_dict;
        struct sql_dict_iterate_context *ctx;
	string_t *query;

	ctx = i_new(struct sql_dict_iterate_context, 1);
	ctx->ctx.dict = _dict;

	t_push();
	query = t_str_new(256);
	str_printfa(query, "SELECT %s, %s FROM %s WHERE %s LIKE '%s/%%'",
		    dict->where_field, dict->select_field,
		    dict->table, dict->where_field, str_escape(path));
	if (!recurse) {
		str_printfa(query, " AND %s NOT LIKE '%s/%%/%%'",
			    dict->where_field, str_escape(path));
	}
	ctx->result = sql_query_s(dict->db, str_c(query));
	t_pop();

	return &ctx->ctx;
}

static int sql_dict_iterate(struct dict_iterate_context *_ctx,
			    const char **key_r, const char **value_r)
{
	struct sql_dict_iterate_context *ctx =
		(struct sql_dict_iterate_context *)_ctx;
	int ret;

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

	ret = sql_transaction_commit_s(&ctx->sql_ctx, &error);
	if (ret < 0)
		i_error("sql dict: commit failed: %s", error);
	i_free(ctx);
	return ret;
}

static void sql_dict_transaction_rollback(struct dict_transaction_context *_ctx)
{
	struct sql_dict_transaction_context *ctx =
		(struct sql_dict_transaction_context *)_ctx;

	sql_transaction_rollback(&ctx->sql_ctx);
	i_free(ctx);
}

static void sql_dict_set(struct dict_transaction_context *_ctx,
			 const char *key, const char *value)
{
	struct sql_dict_transaction_context *ctx =
		(struct sql_dict_transaction_context *)_ctx;
	struct sql_dict *dict = (struct sql_dict *)_ctx->dict;
	const char *query;

	t_push();
	query = t_strdup_printf("UPDATE %s SET %s = '%s' WHERE %s = '%s'",
				dict->table, dict->select_field, str_escape(value),
				dict->where_field, str_escape(key));
	sql_update(ctx->sql_ctx, query);
	t_pop();
}

static void sql_dict_atomic_inc(struct dict_transaction_context *_ctx,
				const char *key, long long diff)
{
	struct sql_dict_transaction_context *ctx =
		(struct sql_dict_transaction_context *)_ctx;
	struct sql_dict *dict = (struct sql_dict *)_ctx->dict;
	const char *query;

	t_push();
	query = t_strdup_printf("UPDATE %s SET %s = %s + %lld WHERE %s = '%s'",
				dict->table, dict->select_field,
				dict->select_field, diff,
				dict->where_field, str_escape(key));
	sql_update(ctx->sql_ctx, query);
	t_pop();
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
		sql_dict_atomic_inc
	}
};

static struct dict *dict_sql_classes;

void dict_sql_register(void)
{
        const struct sql_db *const *drivers;
	unsigned int i, count;

	/* @UNSAFE */
	drivers = array_get(&sql_drivers, &count);
	dict_sql_classes = i_new(struct dict, count + 1);

	for (i = 0; i < count; i++) {
		dict_sql_classes[i] = sql_dict;
		dict_sql_classes[i].name = drivers[i]->name;

		dict_class_register(&dict_sql_classes[i]);
	}
}

void dict_sql_unregister(void)
{
	int i;

	for (i = 0; dict_sql_classes[i].name != NULL; i++)
		dict_class_unregister(&dict_sql_classes[i]);
	i_free(dict_sql_classes);
}
