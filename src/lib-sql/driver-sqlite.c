/* Copyright (c) 2006-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "str.h"
#include "hex-binary.h"
#include "sql-api-private.h"

#ifdef BUILD_SQLITE
#include <sqlite3.h>

/* retry time if db is busy (in ms) */
static const int sqlite_busy_timeout = 1000;

struct sqlite_db {
	struct sql_db api;

	pool_t pool;
	const char *dbfile;
	sqlite3 *sqlite;
	bool connected:1;
	int rc;
};

struct sqlite_result {
	struct sql_result api;
	sqlite3_stmt *stmt;
	unsigned int cols;
	const char **row;
};

struct sqlite_transaction_context {
	struct sql_transaction_context ctx;
	bool failed:1;
};

extern const struct sql_db driver_sqlite_db;
extern const struct sql_result driver_sqlite_result;
extern const struct sql_result driver_sqlite_error_result;

static struct event_category event_category_sqlite = {
	.parent = &event_category_sql,
	.name = "sqlite"
};

static int driver_sqlite_connect(struct sql_db *_db)
{
 	struct sqlite_db *db = (struct sqlite_db *)_db;

	if (db->connected)
		return 1;

	db->rc = sqlite3_open(db->dbfile, &db->sqlite);

	if (db->rc == SQLITE_OK) {
		db->connected = TRUE;
		sqlite3_busy_timeout(db->sqlite, sqlite_busy_timeout);
		return 1;
	} else {
		e_error(_db->event, "open(%s) failed: %s", db->dbfile,
			sqlite3_errmsg(db->sqlite));
		sqlite3_close(db->sqlite);
		db->sqlite = NULL;
		return -1;
	}
}

static void driver_sqlite_disconnect(struct sql_db *_db)
{
 	struct sqlite_db *db = (struct sqlite_db *)_db;

	sqlite3_close(db->sqlite);
	db->sqlite = NULL;
}

static int driver_sqlite_init_full_v(const struct sql_settings *set, struct sql_db **db_r,
				     const char **error_r ATTR_UNUSED)
{
	struct sqlite_db *db;
	pool_t pool;

	pool = pool_alloconly_create("sqlite driver", 512);
	db = p_new(pool, struct sqlite_db, 1);
	db->pool = pool;
	db->api = driver_sqlite_db;
	db->dbfile = p_strdup(db->pool, set->connect_string);
	db->connected = FALSE;
	db->api.event = event_create(set->event_parent);
	event_add_category(db->api.event, &event_category_sqlite);
	event_set_append_log_prefix(db->api.event, "sqlite: ");

	*db_r = &db->api;
	return 0;
}

static void driver_sqlite_deinit_v(struct sql_db *_db)
{
	struct sqlite_db *db = (struct sqlite_db *)_db;

	_db->no_reconnect = TRUE;
	sql_db_set_state(&db->api, SQL_DB_STATE_DISCONNECTED);

	sqlite3_close(db->sqlite);
	sql_connection_log_finished(_db);
	event_unref(&_db->event);
	array_free(&_db->module_contexts);
	pool_unref(&db->pool);
}

static const char *
driver_sqlite_escape_string(struct sql_db *_db ATTR_UNUSED,
			    const char *string)
{
	const char *p;
	char *dest, *destbegin;

	/* find the first ' */
	for (p = string; *p != '\''; p++) {
		if (*p == '\0')
			return t_strdup_noconst(string);
	}

	/* @UNSAFE: escape ' with '' */
	dest = destbegin = t_buffer_get((p - string) + strlen(string) * 2 + 1);

	memcpy(dest, string, p - string);
	dest += p - string;

	for (; *p != '\0'; p++) {
		*dest++ = *p;
		if (*p == '\'')
			*dest++ = *p;
	}
	*dest++ = '\0';
	t_buffer_alloc(dest - destbegin);

	return destbegin;
}

static void driver_sqlite_result_log(const struct sql_result *result, const char *query)
{
	struct sqlite_db *db = (struct sqlite_db *)result->db;
	bool failed = !db->connected || (db->rc == SQLITE_OK);
	int duration;
	const char *suffix = "";
	io_loop_time_refresh();

	if (!db->connected) {
		suffix = ": Cannot connect to database";
	} else if (db->rc != SQLITE_OK) {
		suffix = t_strdup_printf(": %s (%d)", sqlite3_errmsg(db->sqlite),
					 db->rc);
	}
	e_debug(sql_query_finished_event(&db->api, result->event, query,
					 failed, &duration)->event(),
		SQL_QUERY_FINISHED_FMT"%s", query, duration, suffix);
}

static void driver_sqlite_exec(struct sql_db *_db, const char *query)
{
	struct sqlite_db *db = (struct sqlite_db *)_db;
	struct sql_result result;

	i_zero(&result);
	result.event = event_create(_db->event);

	/* Other drivers do not include time spent connecting
	   but this simplifies error logging, so we include
	   it here. */
	if (driver_sqlite_connect(_db) < 0) {
		driver_sqlite_result_log(&result, query);
	} else {
		db->rc = sqlite3_exec(db->sqlite, query, NULL, NULL, NULL);
		driver_sqlite_result_log(&result, query);
	}

	event_unref(&result.event);
}

static void driver_sqlite_query(struct sql_db *db, const char *query,
				sql_query_callback_t *callback, void *context)
{
	struct sql_result *result;

	result = sql_query_s(db, query);
	result->callback = TRUE;
	callback(result, context);
	result->callback = FALSE;
	sql_result_unref(result);
}

static struct sql_result *
driver_sqlite_query_s(struct sql_db *_db, const char *query)
{
	struct sqlite_db *db = (struct sqlite_db *)_db;
	struct sqlite_result *result;

	result = i_new(struct sqlite_result, 1);
	result->api.event = event_create(_db->event);

	if (driver_sqlite_connect(_db) < 0) {
		driver_sqlite_result_log(&result->api, query);
		result->api = driver_sqlite_error_result;
		result->stmt = NULL;
		result->cols = 0;
	} else {
		db->rc = sqlite3_prepare(db->sqlite, query, -1, &result->stmt, NULL);
		driver_sqlite_result_log(&result->api, query);
		if (db->rc == SQLITE_OK) {
			result->api = driver_sqlite_result;
			result->cols = sqlite3_column_count(result->stmt);
			result->row = i_new(const char *, result->cols);
		} else {
			result->api = driver_sqlite_error_result;
			result->stmt = NULL;
			result->cols = 0;
		}
	}
	result->api.db = _db;
	result->api.refcount = 1;

	return &result->api;
}

static void driver_sqlite_result_free(struct sql_result *_result)
{
	struct sqlite_result *result = (struct sqlite_result *)_result;
	struct sqlite_db *db = (struct sqlite_db *)	result->api.db;
	int rc;

	if (_result->callback)
		return;

	if (result->stmt != NULL) {
		if ((rc = sqlite3_finalize(result->stmt)) != SQLITE_OK) {
			e_warning(_result->event, "finalize failed: %s (%d)",
				  sqlite3_errmsg(db->sqlite), rc);
		}
		i_free(result->row);
	}
	event_unref(&result->api.event);
	i_free(result);
}

static int driver_sqlite_result_next_row(struct sql_result *_result)
{
	struct sqlite_result *result = (struct sqlite_result *)_result;

	switch (sqlite3_step(result->stmt)) {
	case SQLITE_ROW:
		return 1;
	case SQLITE_DONE:
		return 0;
	default:
		return -1;
	}
}

static unsigned int
driver_sqlite_result_get_fields_count(struct sql_result *_result)
{
	struct sqlite_result *result = (struct sqlite_result *)_result;

	return result->cols;
}

static const char *
driver_sqlite_result_get_field_name(struct sql_result *_result,
				    unsigned int idx)
{
	struct sqlite_result *result = (struct sqlite_result *)_result;

	return sqlite3_column_name(result->stmt, idx);
}

static int driver_sqlite_result_find_field(struct sql_result *_result,
					   const char *field_name)
{
	struct sqlite_result *result = (struct sqlite_result *)_result;
	unsigned int i;

	for (i = 0; i < result->cols; ++i) {
		const char *col = sqlite3_column_name(result->stmt, i);

		if (strcmp(col, field_name) == 0)
			return i;
	}

	return -1;
}

static const char *
driver_sqlite_result_get_field_value(struct sql_result *_result,
				     unsigned int idx)
{
	struct sqlite_result *result = (struct sqlite_result *)_result;

	return (const char*)sqlite3_column_text(result->stmt, idx);
}

static const unsigned char *
driver_sqlite_result_get_field_value_binary(struct sql_result *_result,
					    unsigned int idx, size_t *size_r)
{
	struct sqlite_result *result = (struct sqlite_result *)_result;

	*size_r = sqlite3_column_bytes(result->stmt, idx);
	return sqlite3_column_blob(result->stmt, idx);
}

static const char *
driver_sqlite_result_find_field_value(struct sql_result *result,
				     const char *field_name)
{
	int idx;

	idx = driver_sqlite_result_find_field(result, field_name);
	if (idx < 0)
		return NULL;
	return driver_sqlite_result_get_field_value(result, idx);
}

static const char *const *
driver_sqlite_result_get_values(struct sql_result *_result)
{
	struct sqlite_result *result = (struct sqlite_result *)_result;
	unsigned int i;

	for (i = 0; i < result->cols; ++i) {
		result->row[i] =
			driver_sqlite_result_get_field_value(_result, i);
	}

	return (const char *const *)result->row;
}

static const char *driver_sqlite_result_get_error(struct sql_result *_result)
{
	struct sqlite_result *result = (struct sqlite_result *)_result;
	struct sqlite_db *db = (struct sqlite_db *)result->api.db;

	return sqlite3_errmsg(db->sqlite);
}

static struct sql_transaction_context *
driver_sqlite_transaction_begin(struct sql_db *_db)
{
	struct sqlite_transaction_context *ctx;
	struct sqlite_db *db = (struct sqlite_db *)_db;

	ctx = i_new(struct sqlite_transaction_context, 1);
	ctx->ctx.db = _db;
	ctx->ctx.event = event_create(_db->event);

	sql_exec(_db, "BEGIN TRANSACTION");
	if (db->rc != SQLITE_OK)
		ctx->failed = TRUE;

	return &ctx->ctx;
}

static void
driver_sqlite_transaction_rollback(struct sql_transaction_context *_ctx)
{
	struct sqlite_transaction_context *ctx =
		(struct sqlite_transaction_context *)_ctx;

	if (!ctx->failed) {
		e_debug(sql_transaction_finished_event(_ctx)->
			add_str("error", "Rolled back")->event(),
			"Transaction rolled back");
	}
	sql_exec(_ctx->db, "ROLLBACK");
	event_unref(&_ctx->event);
	i_free(ctx);
}

static void
driver_sqlite_transaction_commit(struct sql_transaction_context *_ctx,
				 sql_commit_callback_t *callback, void *context)
{
	struct sqlite_transaction_context *ctx =
		(struct sqlite_transaction_context *)_ctx;
	struct sqlite_db *db = (struct sqlite_db *)ctx->ctx.db;
	struct sql_commit_result commit_result;

	if (!ctx->failed) {
		sql_exec(_ctx->db, "COMMIT");
		if (db->rc != SQLITE_OK)
			ctx->failed = TRUE;
	}

	i_zero(&commit_result);
	if (ctx->failed) {
		commit_result.error = sqlite3_errmsg(db->sqlite);
		callback(&commit_result, context);
		e_debug(sql_transaction_finished_event(_ctx)->
			add_str("error", commit_result.error)->event(),
			"Transaction failed");
		/* From SQLite manual: It is recommended that applications
		   respond to the errors listed above by explicitly issuing a
		   ROLLBACK command. If the transaction has already been rolled
		   back automatically by the error response, then the ROLLBACK
		   command will fail with an error, but no harm is caused by
		   this. */
		driver_sqlite_transaction_rollback(_ctx);
	} else {
		e_debug(sql_transaction_finished_event(_ctx)->event(),
			"Transaction committed");
		callback(&commit_result, context);
		event_unref(&_ctx->event);
		i_free(ctx);
	}
}

static int
driver_sqlite_transaction_commit_s(struct sql_transaction_context *_ctx,
				   const char **error_r)
{
	struct sqlite_transaction_context *ctx =
		(struct sqlite_transaction_context *)_ctx;
	struct sqlite_db *db = (struct sqlite_db *) ctx->ctx.db;

	if (ctx->failed) {
		/* also does i_free(ctx) */
		driver_sqlite_transaction_rollback(_ctx);
		return -1;
	}

	sql_exec(_ctx->db, "COMMIT");
	*error_r = sqlite3_errmsg(db->sqlite);
	i_free(ctx);
	return 0;
}

static void
driver_sqlite_update(struct sql_transaction_context *_ctx, const char *query,
		     unsigned int *affected_rows)
{
	struct sqlite_transaction_context *ctx =
		(struct sqlite_transaction_context *)_ctx;
	struct sqlite_db *db = (struct sqlite_db *)ctx->ctx.db;

	if (ctx->failed)
		return;

	sql_exec(_ctx->db, query);
	if (db->rc != SQLITE_OK)
		ctx->failed = TRUE;
	else if (affected_rows != NULL)
		*affected_rows = sqlite3_changes(db->sqlite);
}

static const char *
driver_sqlite_escape_blob(struct sql_db *_db ATTR_UNUSED,
			  const unsigned char *data, size_t size)
{
	string_t *str = t_str_new(128);

	str_append(str, "x'");
	binary_to_hex_append(str, data, size);
	str_append_c(str, '\'');
	return str_c(str);
}

const struct sql_db driver_sqlite_db = {
	.name = "sqlite",
	.flags = SQL_DB_FLAG_BLOCKING,

	.v = {
		.init_full = driver_sqlite_init_full_v,
		.deinit = driver_sqlite_deinit_v,
		.connect = driver_sqlite_connect,
		.disconnect = driver_sqlite_disconnect,
		.escape_string = driver_sqlite_escape_string,
		.exec = driver_sqlite_exec,
		.query = driver_sqlite_query,
		.query_s = driver_sqlite_query_s,

		.transaction_begin = driver_sqlite_transaction_begin,
		.transaction_commit = driver_sqlite_transaction_commit,
		.transaction_commit_s = driver_sqlite_transaction_commit_s,
		.transaction_rollback = driver_sqlite_transaction_rollback,

		.update = driver_sqlite_update,

		.escape_blob = driver_sqlite_escape_blob,
	}
};

const struct sql_result driver_sqlite_result = {
	.v = {
		.free = driver_sqlite_result_free,
		.next_row = driver_sqlite_result_next_row,
		.get_fields_count = driver_sqlite_result_get_fields_count,
		.get_field_name = driver_sqlite_result_get_field_name,
		.find_field = driver_sqlite_result_find_field,
		.get_field_value = driver_sqlite_result_get_field_value,
		.get_field_value_binary = driver_sqlite_result_get_field_value_binary,
		.find_field_value = driver_sqlite_result_find_field_value,
		.get_values = driver_sqlite_result_get_values,
		.get_error = driver_sqlite_result_get_error,
	}
};

static int
driver_sqlite_result_error_next_row(struct sql_result *result ATTR_UNUSED)
{
	return -1;
}

const struct sql_result driver_sqlite_error_result = {
	.v = {
		.free = driver_sqlite_result_free,
		.next_row = driver_sqlite_result_error_next_row,
		.get_error = driver_sqlite_result_get_error,
	}
};

const char *driver_sqlite_version = DOVECOT_ABI_VERSION;

void driver_sqlite_init(void);
void driver_sqlite_deinit(void);

void driver_sqlite_init(void)
{
	sql_driver_register(&driver_sqlite_db);
}

void driver_sqlite_deinit(void)
{
	sql_driver_unregister(&driver_sqlite_db);
}

#endif
