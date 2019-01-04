/* Copyright (c) 2017-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "test-lib.h"
#include "str.h"
#include "buffer.h"
#include "sql-api-private.h"
#include "driver-test.h"
#include "array.h"
#include "hex-binary.h"

struct test_sql_db {
	struct sql_db api;

	pool_t pool;
	ARRAY(struct test_driver_result) expected;
	const char *error;
	bool failed:1;
};

struct test_sql_result {
	struct sql_result api;
	struct test_driver_result *result;
	const char *error;
};

static struct sql_db *driver_test_mysql_init(const char *connect_string);
static struct sql_db *driver_test_cassandra_init(const char *connect_string);
static struct sql_db *driver_test_sqlite_init(const char *connect_string);
static void driver_test_deinit(struct sql_db *_db);
static int driver_test_connect(struct sql_db *_db);
static void driver_test_disconnect(struct sql_db *_db);
static const char *
driver_test_mysql_escape_string(struct sql_db *_db, const char *string);
static const char *
driver_test_escape_string(struct sql_db *_db, const char *string);
static void driver_test_exec(struct sql_db *_db, const char *query);
static void driver_test_query(struct sql_db *_db, const char *query,
			       sql_query_callback_t *callback, void *context);
static struct sql_result *
driver_test_query_s(struct sql_db *_db, const char *query);
static struct sql_transaction_context *
driver_test_transaction_begin(struct sql_db *_db);
static void driver_test_transaction_commit(struct sql_transaction_context *ctx,
					    sql_commit_callback_t *callback,
					    void *context);
static int
driver_test_transaction_commit_s(struct sql_transaction_context *ctx,
				  const char **error_r);
static void
driver_test_transaction_rollback(struct sql_transaction_context *ctx);
static void
driver_test_update(struct sql_transaction_context *ctx, const char *query,
		    unsigned int *affected_rows);
static const char *
driver_test_mysql_escape_blob(struct sql_db *_db, const unsigned char *data,
			 size_t size);
static const char *
driver_test_escape_blob(struct sql_db *_db, const unsigned char *data,
			 size_t size);

static void driver_test_result_free(struct sql_result *result);
static int driver_test_result_next_row(struct sql_result *result);

static unsigned int
driver_test_result_get_fields_count(struct sql_result *result);
static const char *
driver_test_result_get_field_name(struct sql_result *result, unsigned int idx);
static int
driver_test_result_find_field(struct sql_result *result, const char *field_name);

static const char *
driver_test_result_get_field_value(struct sql_result *result, unsigned int idx);
static const unsigned char *
driver_test_result_get_field_value_binary(struct sql_result *result,
					   unsigned int idx, size_t *size_r);
static const char *
driver_test_result_find_field_value(struct sql_result *result,
				     const char *field_name);
static const char *const *
driver_test_result_get_values(struct sql_result *result);

const char *driver_test_result_get_error(struct sql_result *result);


const struct sql_db driver_test_mysql_db = {
	.name = "mysql",

	.v = {
		.init = driver_test_mysql_init,
		.deinit = driver_test_deinit,
		.connect = driver_test_connect,
		.disconnect = driver_test_disconnect,
		.escape_string = driver_test_mysql_escape_string,
		.exec = driver_test_exec,
		.query = driver_test_query,
		.query_s = driver_test_query_s,

		.transaction_begin = driver_test_transaction_begin,
		.transaction_commit = driver_test_transaction_commit,
		.transaction_commit_s = driver_test_transaction_commit_s,
		.transaction_rollback = driver_test_transaction_rollback,
		.update = driver_test_update,

		.escape_blob = driver_test_mysql_escape_blob,
	}
};

const struct sql_db driver_test_cassandra_db = {
	.name = "cassandra",

	.v = {
		.init = driver_test_cassandra_init,
		.deinit = driver_test_deinit,
		.connect = driver_test_connect,
		.disconnect = driver_test_disconnect,
		.escape_string = driver_test_escape_string,
		.exec = driver_test_exec,
		.query = driver_test_query,
		.query_s = driver_test_query_s,

		.transaction_begin = driver_test_transaction_begin,
		.transaction_commit = driver_test_transaction_commit,
		.transaction_commit_s = driver_test_transaction_commit_s,
		.transaction_rollback = driver_test_transaction_rollback,
		.update = driver_test_update,

		.escape_blob = driver_test_escape_blob,
	}
};

const struct sql_db driver_test_sqlite_db = {
	.name = "sqlite",

	.v = {
		.init = driver_test_sqlite_init,
		.deinit = driver_test_deinit,
		.connect = driver_test_connect,
		.disconnect = driver_test_disconnect,
		.escape_string = driver_test_escape_string,
		.exec = driver_test_exec,
		.query = driver_test_query,
		.query_s = driver_test_query_s,

		.transaction_begin = driver_test_transaction_begin,
		.transaction_commit = driver_test_transaction_commit,
		.transaction_commit_s = driver_test_transaction_commit_s,
		.transaction_rollback = driver_test_transaction_rollback,
		.update = driver_test_update,

		.escape_blob = driver_test_escape_blob,
	}
};


const struct sql_result driver_test_result = {
	.v = {
		.free = driver_test_result_free,
		.next_row = driver_test_result_next_row,
		.get_fields_count = driver_test_result_get_fields_count,
		.get_field_name = driver_test_result_get_field_name,
		.find_field = driver_test_result_find_field,
		.get_field_value = driver_test_result_get_field_value,
		.get_field_value_binary = driver_test_result_get_field_value_binary,
		.find_field_value = driver_test_result_find_field_value,
		.get_values = driver_test_result_get_values,
		.get_error = driver_test_result_get_error,
	}
};

void sql_driver_test_register(void)
{
	sql_driver_register(&driver_test_mysql_db);
	sql_driver_register(&driver_test_cassandra_db);
	sql_driver_register(&driver_test_sqlite_db);
}

void sql_driver_test_unregister(void)
{
	sql_driver_unregister(&driver_test_mysql_db);
	sql_driver_unregister(&driver_test_cassandra_db);
	sql_driver_unregister(&driver_test_sqlite_db);
}

static struct sql_db *driver_test_init(const struct sql_db *driver,
					const char *connect_string ATTR_UNUSED)
{
	pool_t pool = pool_alloconly_create(MEMPOOL_GROWING" test sql driver", 2048);
	struct test_sql_db *ret = p_new(pool, struct test_sql_db, 1);
	ret->pool = pool;
	ret->api = *driver;
	p_array_init(&ret->expected, pool, 8);
	return &ret->api;
}

static struct sql_db *driver_test_mysql_init(const char *connect_string)
{
	return driver_test_init(&driver_test_mysql_db, connect_string);
}

static struct sql_db *driver_test_cassandra_init(const char *connect_string)
{
	return driver_test_init(&driver_test_cassandra_db, connect_string);
}

static struct sql_db *driver_test_sqlite_init(const char *connect_string)
{
	return driver_test_init(&driver_test_sqlite_db, connect_string);
}

static void driver_test_deinit(struct sql_db *_db ATTR_UNUSED)
{
	struct test_sql_db *db = (struct test_sql_db*)_db;
	array_free(&_db->module_contexts);
	pool_unref(&db->pool);
}

static int driver_test_connect(struct sql_db *_db ATTR_UNUSED)
{
	/* nix */
	return 0;
}

static void driver_test_disconnect(struct sql_db *_db ATTR_UNUSED)
{ }

static const char *
driver_test_mysql_escape_string(struct sql_db *_db ATTR_UNUSED,
				 const char *string)
{
	string_t *esc = t_str_new(strlen(string));
	for(const char *ptr = string; *ptr != '\0'; ptr++) {
		if (*ptr == '\n' || *ptr == '\r' || *ptr == '\\' ||
		    *ptr == '\'' || *ptr == '\"' || *ptr == '\x1a')
			str_append_c(esc, '\\');
		str_append_c(esc, *ptr);
	}
	return str_c(esc);
}

static const char *
driver_test_escape_string(struct sql_db *_db ATTR_UNUSED, const char *string)
{
	return string;
}

static void driver_test_exec(struct sql_db *_db, const char *query)
{
	struct test_sql_db *db = (struct test_sql_db*)_db;
	struct test_driver_result *result =
		array_first_modifiable(&db->expected);
	i_assert(result->cur < result->nqueries);

/*	i_debug("DUMMY EXECUTE: %s", query);
	i_debug("DUMMY EXPECT : %s", result->queries[result->cur]); */

	test_assert(strcmp(result->queries[result->cur], query)==0);

	if (strcmp(result->queries[result->cur], query) != 0) {
		db->error = "Invalid query";
		db->failed = TRUE;
	}

	result->cur++;
}

static void
driver_test_query(struct sql_db *_db, const char *query,
		   sql_query_callback_t *callback, void *context)
{
	struct sql_result *result = driver_test_query_s(_db, query);
	if (callback != NULL)
		callback(result, context);
}

static struct sql_result *
driver_test_query_s(struct sql_db *_db, const char *query)
{
	struct test_sql_db *db = (struct test_sql_db*)_db;
	struct test_driver_result *result =
		array_first_modifiable(&db->expected);
	struct test_sql_result *res = i_new(struct test_sql_result, 1);

	driver_test_exec(_db, query);

	if (db->failed) {
		res->api.failed = TRUE;
	}

	res->api.v = driver_test_result.v;
	res->api.db = _db;
	if (result->result != NULL) {
		res->result = i_new(struct test_driver_result, 1);
		memcpy(res->result, result, sizeof(*result));
	}
	res->api.refcount = 1;

	/* drop it from array if it's used up */
	if (result->cur == result->nqueries)
		array_delete(&db->expected, 0, 1);

	return &res->api;
}

static struct sql_transaction_context *
driver_test_transaction_begin(struct sql_db *_db)
{
	struct sql_transaction_context *ctx =
		i_new(struct sql_transaction_context, 1);
	ctx->db = _db;
	return ctx;
}

static void
driver_test_transaction_commit(struct sql_transaction_context *ctx,
				sql_commit_callback_t *callback, void *context)
{
	struct sql_commit_result res;
	res.error_type = driver_test_transaction_commit_s(ctx, &res.error);
	callback(&res, context);
}

static int
driver_test_transaction_commit_s(struct sql_transaction_context *ctx,
				  const char **error_r)
{
	struct test_sql_db *db = (struct test_sql_db*)ctx->db;
	int ret = 0;

	if (db->error != NULL) {
		*error_r = db->error;
		ret = -1;
	}
	i_free(ctx);
	db->error = NULL;
	db->failed = FALSE;

	return ret;
}

static void
driver_test_transaction_rollback(struct sql_transaction_context *ctx)
{
	struct test_sql_db *db = (struct test_sql_db*)ctx->db;
	i_free(ctx);
	db->error = NULL;
	db->failed = FALSE;
}

static void
driver_test_update(struct sql_transaction_context *ctx, const char *query,
		    unsigned int *affected_rows)
{
	struct test_sql_db *db= (struct test_sql_db*)ctx->db;
	struct test_driver_result *result =
		array_first_modifiable(&db->expected);
	driver_test_exec(ctx->db, query);

	if (affected_rows != NULL)
		*affected_rows = result->affected_rows;

	/* drop it from array if it's used up */
	if (result->cur == result->nqueries)
		array_delete(&db->expected, 0, 1);
}

static const char *
driver_test_mysql_escape_blob(struct sql_db *_db ATTR_UNUSED,
			       const unsigned char *data, size_t size)
{
	return t_strdup_printf("X'%s'", binary_to_hex(data,size));
}

static const char *
driver_test_escape_blob(struct sql_db *_db ATTR_UNUSED,
			 const unsigned char *data, size_t size)
{
	return t_strdup_printf("X'%s'", binary_to_hex(data,size));
}

static void driver_test_result_free(struct sql_result *result)
{
        struct test_sql_result *tsr =
                (struct test_sql_result *)result;
	if (tsr->result != NULL)
		i_free(tsr->result);
	i_free(result);
}

static int driver_test_result_next_row(struct sql_result *result)
{
	struct test_sql_result *tsr =
		(struct test_sql_result *)result;
	struct test_driver_result *r = tsr->result;

	if (r == NULL) return 0;

	struct test_driver_result_set *rs =
		&(r->result[r->cur-1]);
	if (rs->cur <= rs->rows) {
		rs->cur++;
	}

	return rs->cur <= rs->rows ? 1 : 0;
}

static unsigned int
driver_test_result_get_fields_count(struct sql_result *result)
{
        struct test_sql_result *tsr =
                (struct test_sql_result *)result;
        struct test_driver_result *r = tsr->result;
	struct test_driver_result_set *rs =
		&(r->result[r->cur-1]);
	return rs->cols;
}

static const char *
driver_test_result_get_field_name(struct sql_result *result, unsigned int idx)
{
        struct test_sql_result *tsr =
                (struct test_sql_result *)result;
        struct test_driver_result *r = tsr->result;
	struct test_driver_result_set *rs =
		&(r->result[r->cur-1]);
	i_assert(idx < rs->cols);
	return rs->col_names[idx];
}

static int
driver_test_result_find_field(struct sql_result *result, const char *field_name)
{
        struct test_sql_result *tsr =
                (struct test_sql_result *)result;
        struct test_driver_result *r = tsr->result;
	struct test_driver_result_set *rs =
		&(r->result[r->cur-1]);
	for(size_t i = 0; i < rs->cols; i++) {
		if (strcmp(field_name, rs->col_names[i])==0)
			return i;
	}
	return -1;
}

static const char *
driver_test_result_get_field_value(struct sql_result *result, unsigned int idx)
{
        struct test_sql_result *tsr =
                (struct test_sql_result *)result;
        struct test_driver_result *r = tsr->result;
	struct test_driver_result_set *rs =
		&(r->result[r->cur-1]);

	i_assert(idx < rs->cols);
	i_assert(rs->cur <= rs->rows);

	return rs->row_data[rs->cur-1][idx];
}
static const unsigned char *
driver_test_result_get_field_value_binary(struct sql_result *result,
					   unsigned int idx, size_t *size_r)
{
	buffer_t *buf = t_buffer_create(64);
	const char *value = driver_test_result_get_field_value(result, idx);
	/* expect it hex encoded */
	if (hex_to_binary(value, buf) < 0) {
		*size_r = 0;
		return NULL;
	}
	*size_r = buf->used;
	return buf->data;
}
static const char *
driver_test_result_find_field_value(struct sql_result *result,
				     const char *field_name)
{
	int idx = driver_test_result_find_field(result, field_name);
	if (idx < 0) return NULL;
	return driver_test_result_get_field_value(result, idx);
}
static const char *const *
driver_test_result_get_values(struct sql_result *result)
{
        struct test_sql_result *tsr =
                (struct test_sql_result *)result;
        struct test_driver_result *r = tsr->result;
	struct test_driver_result_set *rs =
		&(r->result[r->cur-1]);
	i_assert(rs->cur <= rs->rows);
	return rs->row_data[rs->cur-1];
}

const char *driver_test_result_get_error(struct sql_result *result)
{
        struct test_sql_result *tsr =
                (struct test_sql_result *)result;
	return tsr->error;
}


void sql_driver_test_add_expected_result(struct sql_db *_db,
					  const struct test_driver_result *result)
{
	struct test_sql_db *db = (struct test_sql_db*)_db;
	array_append(&db->expected, result, 1);
}

void sql_driver_test_clear_expected_results(struct sql_db *_db)
{
	struct test_sql_db *db = (struct test_sql_db*)_db;
	array_clear(&db->expected);
}
