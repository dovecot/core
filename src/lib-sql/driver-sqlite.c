/* Copyright (c) 2006-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "eacces-error.h"
#include "array.h"
#include "hash.h"
#include "llist.h"
#include "ioloop.h"
#include "str.h"
#include "hex-binary.h"
#include "sql-api-private.h"
#include "strfuncs.h"
#include "str-parse.h"
#include "settings.h"
#include "settings-parser.h"

#ifdef BUILD_SQLITE
#include <sqlite3.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

/* retry time if db is busy (in ms) */
static const int sqlite_busy_timeout = 1000;

struct sqlite_db {
	struct sql_db api;

	sqlite3 *sqlite;
	const struct sqlite_settings *set;
	int connect_rc;
	int connect_errno;
	bool connected:1;
};

struct sqlite_prepared_statement {
	struct sql_prepared_statement api;
	sqlite3_stmt *handle;
	char *error;
	/* Prepared statement cannot be used concurrently by multiple statements */
	bool locked:1;
};

struct sqlite_statement {
	struct sql_statement api;
	struct sqlite_prepared_statement *prep_stmt;
	sqlite3_stmt *handle;
	const char *error;
	int rc;
};

struct sqlite_result {
	struct sql_result api;
	struct sqlite_statement *stmt;
	unsigned int cols;
	int rc;
	char *error;
	const char **row;
};

struct sqlite_transaction_context {
	struct sql_transaction_context ctx;
	int rc;
	char *error;
};

/* <settings checks> */
struct sqlite_settings {
	pool_t pool;

	const char *path;
	const char *journal_mode;
	bool readonly;

	/* generated: */
	bool parsed_journal_use_wal;
};
/* </settings checks> */

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("sqlite_"#name, name, struct sqlite_settings)
static const struct setting_define sqlite_setting_defines[] = {
	DEF(STR, path),
	DEF(ENUM, journal_mode),
	DEF(BOOL, readonly),

	SETTING_DEFINE_LIST_END
};
static const struct sqlite_settings sqlite_default_settings = {
	.path = "",
	.journal_mode = "wal:delete",
	.readonly = FALSE,
};
static bool
driver_sqlite_settings_check(void *_set, pool_t pool, const char **error_r);
const struct setting_parser_info sqlite_setting_parser_info = {
	.name = "sqlite",
#ifdef SQL_DRIVER_PLUGINS
	.plugin_dependency = "libdriver_sqlite",
#endif

	.defines = sqlite_setting_defines,
	.defaults = &sqlite_default_settings,

	.struct_size = sizeof(struct sqlite_settings),
	.pool_offset1 = 1 + offsetof(struct sqlite_settings, pool),

	.check_func = driver_sqlite_settings_check,
};

/* <settings checks> */
static bool driver_sqlite_settings_check(void *_set, pool_t pool ATTR_UNUSED,
					 const char **error_r ATTR_UNUSED)
{
	struct sqlite_settings *set = _set;
	set->parsed_journal_use_wal = strcmp(set->journal_mode, "wal") == 0;
	return TRUE;
}
/* </settings checks> */

extern const struct sql_db driver_sqlite_db;
extern const struct sql_result driver_sqlite_result;
extern const struct sql_result driver_sqlite_error_result;

static ARRAY(struct sqlite_db *) sqlite_db_cache;

static struct event_category event_category_sqlite = {
	.parent = &event_category_sql,
	.name = "sqlite"
};

#define SQLITE_IS_OK(rc) ((rc) == SQLITE_OK || (rc) == SQLITE_DONE)

static const char*
driver_sqlite_result_str(struct sql_db *_db, int rc);
static int
driver_sqlite_prepared_statement_reopen(struct sqlite_db *db,
					struct sqlite_prepared_statement *stmt);

static void driver_sqlite_finalize_handle(struct sql_db *db,
					  struct sqlite3_stmt **_handle,
					  const char *query)
{
	sqlite3_stmt *handle = *_handle;
	i_assert(handle != NULL);
	*_handle = NULL;

	int rc = sqlite3_finalize(handle);
	if (rc == SQLITE_NOMEM) {
		i_fatal_status(FATAL_OUTOFMEM, "sqlite3_finalize(%s) failed: %s (%d)",
			       query, sqlite3_errstr(rc), rc);
	} else if (rc != SQLITE_OK) {
		const char *errstr = driver_sqlite_result_str(db, rc);
		e_debug(db->event, "sqlite3_finalize(%s) failed: %s",
			query, errstr);
	}
}

static void driver_sqlite_finalize_prepared_statements(struct sqlite_db *db)
{
	if (!hash_table_is_created(db->api.prepared_stmt_hash))
		return;
	struct hash_iterate_context *iter =
		hash_table_iterate_init(db->api.prepared_stmt_hash);
	char *key ATTR_UNUSED;
	struct sql_prepared_statement *value;

	while (hash_table_iterate(iter, db->api.prepared_stmt_hash, &key, &value)) {
		/* finalize handle */
		struct sqlite_prepared_statement *stmt =
			container_of(value, struct sqlite_prepared_statement, api);
		if (stmt->handle != NULL)
			driver_sqlite_finalize_handle(&db->api, &stmt->handle,
						      stmt->api.query_template);
	}

	hash_table_iterate_deinit(&iter);
}

static void driver_sqlite_reopen_prepared_statements(struct sqlite_db *db)
{
	if (!hash_table_is_created(db->api.prepared_stmt_hash))
		return;
	struct hash_iterate_context *iter =
		hash_table_iterate_init(db->api.prepared_stmt_hash);
	char *key ATTR_UNUSED;
	struct sql_prepared_statement *value;

	while (hash_table_iterate(iter, db->api.prepared_stmt_hash, &key, &value)) {
		struct sqlite_prepared_statement *stmt =
			container_of(value, struct sqlite_prepared_statement, api);
		driver_sqlite_prepared_statement_reopen(db, stmt);
	}

	hash_table_iterate_deinit(&iter);
}

static void driver_sqlite_disconnect(struct sql_db *_db)
{
	struct sqlite_db *db = container_of(_db, struct sqlite_db, api);

	sql_connection_log_finished(_db);
	driver_sqlite_finalize_prepared_statements(db);
	int rc = sqlite3_close(db->sqlite);
	if (rc != SQLITE_OK) {
		e_error(db->api.event, "sqlite3_close() failed: %s (%d)",
			sqlite3_errstr(rc), rc);
	}
	db->sqlite = NULL;
	db->connected = FALSE;
}

static const char *
driver_sqlite_get_eacces_error(struct sqlite_db *db, const char *func)
{
	const char *path = db->set->path;
	struct stat st ATTR_UNUSED;
	int system_errno;
	if (db->connected)
		system_errno = sqlite3_system_errno(db->sqlite);
	else
		system_errno = db->connect_errno;

	/* Something must've failed */
	i_assert(system_errno != 0);

	/* If we are using wal mode and the database file itself
	   is there, then the problem is likely in the -wal file. */
	if (db->set->parsed_journal_use_wal && system_errno != ENOENT)
		path = t_strconcat(path, "-wal", NULL);

	/* If the path (wal file or database) is not there, it's gonna be
	   creation error. */
	if (system_errno == EACCES) {
		if (stat(path, &st) < 0 && errno == ENOENT)
			return eacces_error_get_creating("creat", path);
		else
			return eacces_error_get(func, path);
	} else {
		/* something else failed */
		return t_strdup_printf("%s(%s) failed: %s", func, db->set->path,
				       strerror(system_errno));
	}
}

static const char *driver_sqlite_connect_error(struct sqlite_db *db)
{
	const char *err;

	switch (db->connect_rc) {
	/* Should not end here with OK */
	case SQLITE_OK:
		i_unreached();
	case SQLITE_CANTOPEN:
	case SQLITE_PERM:
		err = driver_sqlite_get_eacces_error(db, "open");
		break;
	case SQLITE_NOMEM:
		i_fatal_status(FATAL_OUTOFMEM, "open(%s) failed: %s",
			       db->set->path, sqlite3_errstr(db->connect_rc));
	default:
		err = t_strdup_printf("open(%s) failed: %s", db->set->path,
				      sqlite3_errstr(db->connect_rc));
		break;
	}
	return err;
}

static int driver_sqlite_connect(struct sql_db *_db)
{
	struct sqlite_db *db = container_of(_db, struct sqlite_db, api);
	/* this is default for sqlite_open */
	int flags;

	if (db->connected)
		return 1;
	if (db->set->readonly || db->connect_rc == SQLITE_READONLY)
		flags = SQLITE_OPEN_READONLY;
	else
		flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE;

	if (db->set->parsed_journal_use_wal)
		flags |= SQLITE_OPEN_WAL;

	db->connect_rc = sqlite3_open_v2(db->set->path, &db->sqlite, flags, NULL);
	db->connect_errno = sqlite3_system_errno(db->sqlite);

	switch (db->connect_rc) {
	case SQLITE_OK:
		db->connected = TRUE;
		sqlite3_busy_timeout(db->sqlite, sqlite_busy_timeout);
		driver_sqlite_reopen_prepared_statements(db);
		return 1;
	case SQLITE_READONLY:
		i_assert(!db->set->readonly);
		return driver_sqlite_connect(_db);
	default:
		i_free(_db->last_connect_error);
		_db->last_connect_error =
			i_strdup(driver_sqlite_connect_error(db));
		e_error(_db->event, "%s", _db->last_connect_error);
		break;
	}

	driver_sqlite_disconnect(_db);
	return -1;
}

static struct sqlite_db *
driver_sqlite_db_cache_find(const struct sqlite_settings *set)
{
	struct sqlite_db *db;

	array_foreach_elem(&sqlite_db_cache, db) {
		if (settings_equal(&sqlite_setting_parser_info,
				   set, db->set, NULL))
			return db;
	}
	return NULL;
}

static struct sqlite_db *
driver_sqlite_init_from_set(struct event *event,
			    const struct sqlite_settings *set)
{
	struct sqlite_db *db;

	db = i_new(struct sqlite_db, 1);
	db->api = driver_sqlite_db;
	db->set = set;
	db->connected = FALSE;
	db->api.event = event_create(event);
	event_add_category(db->api.event, &event_category_sqlite);
	event_add_str(db->api.event, "sql_driver", "sqlite");
	event_set_append_log_prefix(db->api.event, "sqlite: ");
	return db;
}

static int
driver_sqlite_init_v(struct event *event, struct sql_db **db_r,
		     const char **error_r)
{
	const struct sqlite_settings *set;

	if (settings_get(event, &sqlite_setting_parser_info, 0,
			 &set, error_r) < 0)
		return -1;

	struct sqlite_db *db = driver_sqlite_db_cache_find(set);
	if (db != NULL)
		settings_free(set);
	else {
		db = driver_sqlite_init_from_set(event, set);
		sql_init_common(&db->api);
		array_push_back(&sqlite_db_cache, &db);
		/* Add an extra reference to the db, so it won't be freed while
		   it's still in the cache array. */
	}
	db->api.refcount++;

	*db_r = &db->api;
	return 0;
}

static void driver_sqlite_deinit_v(struct sql_db *_db)
{
	struct sqlite_db *db = container_of(_db, struct sqlite_db, api);

	_db->no_reconnect = TRUE;
	sql_db_set_state(&db->api, SQL_DB_STATE_DISCONNECTED);

	driver_sqlite_disconnect(_db);
	settings_free(db->set);
	event_unref(&_db->event);
	array_free(&_db->module_contexts);
	i_free(db);
}

static const char *
driver_sqlite_escape_string(struct sql_db *_db ATTR_UNUSED,
			    const char *string)
{
	const size_t len = strlen(string) * 2 + 1;
	char *escaped = t_malloc_no0(len);
	if (sqlite3_snprintf(len, escaped, "%q", string) == NULL)
		i_unreached();
	return escaped;
}

static const char *driver_sqlite_readonly_error(struct sqlite_db *db)
{
	int ret = i_faccessat2(AT_FDCWD, db->set->path, W_OK, AT_EACCESS);
	if (ret < 0 && errno == EACCES)
		return eacces_error_get("write", db->set->path);
	else if (ret < 0) {
		/* Something else failed */
	} else if (db->set->parsed_journal_use_wal) {
		const char *path = t_strconcat(db->set->path, "-wal", NULL);
		/* If we ended up here, these things have happened:
		    - the database is unexpectedly readonly
		    - this can only happen if the database itself is non-writable,
		      or the wal file cannot be created, or written to.

		   So here we test if -wal file writing would fail with
		   ENOENT which means the file isn't there, so it likely
		   failed to create it, because the database itself was accessible,
		   and this is likely because permissions. Or it is there,
		   and we get EACCES, and handle it accordingly.
		*/
		ret = i_faccessat2(AT_FDCWD, path, W_OK, AT_EACCESS);
		if (ret < 0) {
			if (errno == ENOENT) {
				return eacces_error_get_creating("creat", path);
			} else if (errno == EACCES) {
				return eacces_error_get("write", path);
			}
		}
	}

	return t_strdup_printf("%s (errno=%d)", sqlite3_errstr(SQLITE_READONLY),
			       sqlite3_system_errno(db->sqlite));
}

static const char*
driver_sqlite_result_str(struct sql_db *_db, int rc)
{
	struct sqlite_db *db = container_of(_db, struct sqlite_db, api);
	const char *err = "";

	if (!db->connected) {
		err = t_strconcat("Cannot connect to database: ",
				  driver_sqlite_connect_error(db), NULL);
	} else if (rc == SQLITE_READONLY) {
		if (db->set->readonly) {
			/* Expected to happen */
			err = t_strdup_printf("%s (because of sqlite_readonly=on)",
					      sqlite3_errstr(rc));
		} else {
			/* Check why the database is read only */
			err = driver_sqlite_readonly_error(db);
		}
	} else if (rc == SQLITE_CANTOPEN || rc == SQLITE_PERM) {
		err = driver_sqlite_get_eacces_error(db, "write");
	} else if (!SQLITE_IS_OK(rc)) {
		err = t_strdup_printf("%s (rc=%d, errno=%d)", sqlite3_errstr(rc),
				      rc, sqlite3_system_errno(db->sqlite));
	}
	return err;
}

static const char *
driver_sqlite_result_log(const struct sqlite_result *result, const char *query)
{
	struct sqlite_db *db = container_of(result->api.db, struct sqlite_db, api);
	bool success = db->connected && SQLITE_IS_OK(result->rc);
	int duration;
	/* result->rc is ignored by driver_sqlite_result_str() when
	   handling connection error. */
	const char *error = driver_sqlite_result_str(result->api.db, result->rc);
	struct event_passthrough *e =
		sql_query_finished_event(&db->api, result->api.event, query, success,
					 &duration);
	io_loop_time_refresh();

	if (!db->connected) {
		e->add_str("error", error);
		e->add_str("error", "Cannot connect to database");
		e->add_int("error_code", db->connect_rc);
	} else if (result->rc == SQLITE_NOMEM) {
		i_fatal_status(FATAL_OUTOFMEM, SQL_QUERY_FINISHED_FMT"%s", query,
			       duration, error);
	} else if (!SQLITE_IS_OK(result->rc)) {
		e->add_str("error", error);
		e->add_int("error_code", result->rc);
	}

	if (*error != '\0')
		error = t_strconcat(": ", error, NULL);

	e_debug(e->event(), SQL_QUERY_FINISHED_FMT"%s", query, duration, error);
	return t_strdup_printf("Query '%s'%s", query, error);
}

static struct sql_statement *
driver_sqlite_statement_init_prepared(struct sql_prepared_statement *_prep_stmt)
{
	struct sqlite_prepared_statement *prep_stmt =
		container_of(_prep_stmt, struct sqlite_prepared_statement, api);
	struct sqlite_db *db = container_of(_prep_stmt->db, struct sqlite_db, api);
	i_assert(!prep_stmt->locked);

	pool_t pool = pool_alloconly_create("sqlite statement", 1024);
	struct sqlite_statement *stmt = p_new(pool, struct sqlite_statement, 1);
	stmt->api.pool = pool;
	stmt->api.db = _prep_stmt->db;
	stmt->api.query_template = _prep_stmt->query_template;

	/* handle is only valid if we are connected */
	if (driver_sqlite_connect(_prep_stmt->db) < 0) {
		i_free(prep_stmt->error);
		prep_stmt->error = i_strdup(
			driver_sqlite_result_str(_prep_stmt->db,
						 db->connect_rc));
	}

	i_assert(prep_stmt->handle != NULL || prep_stmt->error != NULL);

	stmt->error = p_strdup(stmt->api.pool, prep_stmt->error);
	stmt->prep_stmt = prep_stmt;
	stmt->handle = prep_stmt->handle;
	prep_stmt->locked = TRUE;

	return &stmt->api;
}

static void
driver_sqlite_release_prepared_statement(struct sqlite_statement *stmt)
{
	i_assert(stmt->prep_stmt != NULL);
	i_assert(stmt->prep_stmt->locked);

	struct sqlite_prepared_statement *prep_stmt = stmt->prep_stmt;
	prep_stmt->locked = FALSE;
	stmt->prep_stmt = NULL;
	stmt->handle = NULL;

	if (prep_stmt->handle == NULL)
		return;

	sqlite3_reset(prep_stmt->handle);
	sqlite3_clear_bindings(prep_stmt->handle);
}

static struct sql_statement *
driver_sqlite_statement_init(struct sql_db *_db, const char *query_template)
{
	struct sqlite_db *db = container_of(_db, struct sqlite_db, api);
	pool_t pool = pool_alloconly_create("sqlite statement", 1024);
	struct sqlite_statement *stmt = p_new(pool, struct sqlite_statement, 1);
	const char *tail;
	stmt->api.db = _db;
	stmt->api.pool = pool;
	stmt->api.query_template = p_strdup(pool, query_template);

	if (driver_sqlite_connect(_db) < 0) {
		stmt->rc = db->connect_rc;
	} else {
		stmt->rc = sqlite3_prepare_v2(db->sqlite, query_template, -1,
					&stmt->handle, &tail);
	}
	if (!SQLITE_IS_OK(stmt->rc)) {
		stmt->error = p_strdup(pool,
				       driver_sqlite_result_str(_db,
								stmt->rc));
	} else if (*tail != '\0') {
		stmt->error = p_strdup_printf(stmt->api.pool, "'%s' unparsed",
					      tail);
		stmt->rc = SQLITE_ERROR;
	}
	return &stmt->api;
}

static void driver_sqlite_statement_abort(struct sql_statement *_stmt)
{
	struct sqlite_statement *stmt =
		container_of(_stmt, struct sqlite_statement, api);

	if (stmt->prep_stmt != NULL) {
		driver_sqlite_release_prepared_statement(stmt);
	} else if (stmt->handle != NULL) {
		driver_sqlite_finalize_handle(stmt->api.db, &stmt->handle,
					      stmt->api.query_template);
	}

	i_assert(stmt->handle == NULL);
	i_assert(stmt->prep_stmt == NULL);
	pool_unref(&stmt->api.pool);
}

static int driver_sqlite_exec_query(struct sqlite_db *db, const char *query,
				    const char **error_r)
{
	struct sqlite_result result;

	i_zero(&result);
	result.api.db = &db->api;
	result.api.event = event_create(db->api.event);

	/* Other drivers do not include time spent connecting
	   but this simplifies error logging, so we include
	   it here. */
	if (driver_sqlite_connect(&db->api) < 0) {
		*error_r = driver_sqlite_result_log(&result, query);
		result.rc = db->connect_rc;
	} else {
		result.rc = sqlite3_exec(db->sqlite, query, NULL, NULL, NULL);
		*error_r = driver_sqlite_result_log(&result, query);
	}

	event_unref(&result.api.event);
	return result.rc;
}

static void driver_sqlite_exec(struct sql_db *_db, const char *query)
{
	struct sqlite_db *db = container_of(_db, struct sqlite_db, api);
	const char *error;

	(void)driver_sqlite_exec_query(db, query, &error);
}

static struct sqlite_result *
driver_sqlite_statement_result_prepare(struct sqlite_statement *stmt)
{
	struct sqlite_result *result;

	result = i_new(struct sqlite_result, 1);

	if (stmt->error != NULL) {
		result->api = driver_sqlite_error_result;
		result->stmt = stmt;
		result->cols = 0;
		result->error = i_strdup(stmt->error);
		result->rc = stmt->rc;
	} else {
		result->api = driver_sqlite_result;
		result->stmt = stmt;
		result->cols = sqlite3_column_count(result->stmt->handle);
		if (result->cols == 0)
			result->row = NULL;
		else
			result->row = i_new(const char *, result->cols);
	}

	result->api.db = stmt->api.db;
	result->api.refcount = 1;
	result->api.event = event_create(stmt->api.db->event);

	return result;
}

static struct sql_result *
driver_sqlite_query_s(struct sql_db *_db, const char *query)
{
	struct sql_statement *_stmt = driver_sqlite_statement_init(_db, query);
	struct sqlite_statement *stmt =
		container_of(_stmt, struct sqlite_statement, api);
	struct sqlite_result *result =
		driver_sqlite_statement_result_prepare(stmt);
	driver_sqlite_result_log(result, query);

	return &result->api;
}

static void driver_sqlite_result_free(struct sql_result *_result)
{
	struct sqlite_result *result =
		container_of(_result, struct sqlite_result, api);

	if (_result->callback)
		return;

	driver_sqlite_statement_abort(&result->stmt->api);
	result->stmt = NULL;

	event_unref(&result->api.event);
	i_free(result->row);
	i_free(result->error);
	i_free(result);
}

static int driver_sqlite_result_next_row(struct sql_result *_result)
{
	struct sqlite_result *result =
		container_of(_result, struct sqlite_result, api);

	/* no more results */
	if (result->rc == SQLITE_DONE)
		return 0;
	/* there has already been error */
	if (result->rc != SQLITE_OK && result->rc != SQLITE_ROW) {
		i_assert(result->error != NULL);
		return -1;
	}

	result->rc = sqlite3_step(result->stmt->handle);

	switch (result->rc) {
	case SQLITE_ROW:
		return 1;
	case SQLITE_DONE:
		return 0;
	case SQLITE_NOMEM:
		i_fatal_status(FATAL_OUTOFMEM, "sqlite3_step() failed: %s (%d)",
			       sqlite3_errstr(result->rc), SQLITE_NOMEM);
	default:
		i_assert(result->error == NULL);
		result->error = i_strdup(driver_sqlite_result_str(result->api.db,
								  result->rc));
		return -1;
	}
}

static unsigned int
driver_sqlite_result_get_fields_count(struct sql_result *_result)
{
	struct sqlite_result *result =
		container_of(_result, struct sqlite_result, api);

	return result->cols;
}

static const char *
driver_sqlite_result_get_field_name(struct sql_result *_result,
				    unsigned int idx)
{
	struct sqlite_result *result =
		container_of(_result, struct sqlite_result, api);

	return sqlite3_column_name(result->stmt->handle, idx);
}

static int driver_sqlite_result_find_field(struct sql_result *_result,
					   const char *field_name)
{
	struct sqlite_result *result =
		container_of(_result, struct sqlite_result, api);
	unsigned int i;

	for (i = 0; i < result->cols; ++i) {
		const char *col = sqlite3_column_name(result->stmt->handle, i);

		if (strcmp(col, field_name) == 0)
			return i;
	}

	return -1;
}

static const char *
driver_sqlite_result_get_field_value(struct sql_result *_result,
				     unsigned int idx)
{
	struct sqlite_result *result =
		container_of(_result, struct sqlite_result, api);

	return (const char*)sqlite3_column_text(result->stmt->handle, idx);
}

static const unsigned char *
driver_sqlite_result_get_field_value_binary(struct sql_result *_result,
					    unsigned int idx, size_t *size_r)
{
	struct sqlite_result *result =
		container_of(_result, struct sqlite_result, api);

	*size_r = sqlite3_column_bytes(result->stmt->handle, idx);
	return sqlite3_column_blob(result->stmt->handle, idx);
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
	struct sqlite_result *result =
		container_of(_result, struct sqlite_result, api);
	unsigned int i;

	for (i = 0; i < result->cols; ++i) {
		result->row[i] =
			driver_sqlite_result_get_field_value(_result, i);
	}

	return (const char *const *)result->row;
}

static const char *driver_sqlite_result_get_error(struct sql_result *_result)
{
	struct sqlite_result *result =
		container_of(_result, struct sqlite_result, api);
	return result->error;
}

static void
driver_sqlite_transaction_exec(struct sqlite_transaction_context *ctx,
			       const char *query)
{
	struct sqlite_db *db = container_of(ctx->ctx.db, struct sqlite_db, api);
	const char *error;
	int rc;

	/* We have already failed */
	if (!SQLITE_IS_OK(ctx->rc))
		return;

	rc = driver_sqlite_exec_query(db, query, &error);
	if (!SQLITE_IS_OK(rc) && SQLITE_IS_OK(ctx->rc)) {
		/* first error in the transaction */
		i_assert(ctx->error == NULL);
		ctx->rc = rc;
		ctx->error = i_strdup(error);
	}
}

static struct sql_transaction_context *
driver_sqlite_transaction_begin(struct sql_db *_db)
{
	struct sqlite_transaction_context *ctx;

	ctx = i_new(struct sqlite_transaction_context, 1);
	ctx->rc = SQLITE_OK;
	ctx->ctx.db = _db;
	ctx->ctx.event = event_create(_db->event);

	driver_sqlite_transaction_exec(ctx, "BEGIN TRANSACTION");

	return &ctx->ctx;
}

static void
driver_sqlite_transaction_rollback(struct sql_transaction_context *_ctx)
{
	struct sqlite_transaction_context *ctx =
		container_of(_ctx, struct sqlite_transaction_context, ctx);
	struct sqlite_db *db = container_of(_ctx->db, struct sqlite_db, api);

	const char *error;
	int rc = driver_sqlite_exec_query(db, "ROLLBACK", &error);
	if (SQLITE_IS_OK(rc)) {
		e_debug(sql_transaction_finished_event(_ctx)->
			add_str("error", "Rolled back")->event(),
			"Transaction rolled back");
	} else {
		e_debug(sql_transaction_finished_event(_ctx)->
			add_str("error", error)->
			add_int("error_code", rc)->event(),
			"Transaction rollback failed");
	}
	event_unref(&_ctx->event);
	i_free(ctx->error);
	i_free(ctx);
}

static int
driver_sqlite_transaction_commit_s(struct sql_transaction_context *_ctx,
				   const char **error_r)
{
	struct sqlite_transaction_context *ctx =
		container_of(_ctx, struct sqlite_transaction_context, ctx);

	/* If context has already failed, commit won't be run */
	driver_sqlite_transaction_exec(ctx, "COMMIT");
	if (!SQLITE_IS_OK(ctx->rc)) {
		e_debug(sql_transaction_finished_event(_ctx)->
			add_str("error", ctx->error)->event(),
			"Transaction failed: %s", ctx->error);
		*error_r = t_strdup(ctx->error);
		driver_sqlite_transaction_rollback(_ctx);
		return -1;
	}
	e_debug(sql_transaction_finished_event(_ctx)->event(),
		"Transaction committed");
	event_unref(&_ctx->event);
	i_free(ctx);
	return 0;
}

static void
driver_sqlite_update(struct sql_transaction_context *_ctx, const char *query,
		     unsigned int *affected_rows)
{
	struct sqlite_transaction_context *ctx =
		container_of(_ctx, struct sqlite_transaction_context, ctx);
	struct sqlite_db *db = container_of(_ctx->db, struct sqlite_db, api);

	if (!SQLITE_IS_OK(ctx->rc))
		return;

	driver_sqlite_transaction_exec(ctx, query);
	if (ctx->rc == SQLITE_OK && affected_rows != NULL)
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

static struct sql_result *
driver_sqlite_statement_query_s(struct sql_statement *_stmt)
{
	struct sqlite_statement *stmt =
		container_of(_stmt, struct sqlite_statement, api);
	struct sqlite_result *result =
		driver_sqlite_statement_result_prepare(stmt);

	driver_sqlite_result_log(result, sql_statement_get_log_query(_stmt));
	return &result->api;
}

static int
driver_sqlite_prepared_statement_reopen(struct sqlite_db *db,
					struct sqlite_prepared_statement *prep_stmt)
{
	/* Maybe it works this time round */
	i_free(prep_stmt->error);
	prep_stmt->api.db = &db->api;
	 /* driver_sqlite_result_str() ignores rc for connect failures */
	int rc = SQLITE_OK;
	if (driver_sqlite_connect(&db->api) < 0 ||
	    (rc = sqlite3_prepare_v2(db->sqlite, prep_stmt->api.query_template,
				     -1, &prep_stmt->handle, NULL)) != SQLITE_OK) {
		prep_stmt->error =
			i_strdup(driver_sqlite_result_str(&db->api, rc));
		return -1;
	} else {
		e_debug(db->api.event, "Prepared query '%s'",
			prep_stmt->api.query_template);
	}
	return 0;
}

static struct sql_prepared_statement *
driver_sqlite_prepared_statement_init(struct sql_db *_db,
				      const char *query_template)
{
	struct sqlite_db *db = container_of(_db, struct sqlite_db, api);
	struct sqlite_prepared_statement *prep_stmt =
		i_new(struct sqlite_prepared_statement, 1);
	prep_stmt->api.query_template = i_strdup(query_template);
	prep_stmt->api.refcount = 1;
	prep_stmt->api.db = _db;

	(void)driver_sqlite_prepared_statement_reopen(db, prep_stmt);

	return &prep_stmt->api;
}

static void
driver_sqlite_prepared_statement_deinit(struct sql_prepared_statement *_prep_stmt)
{
	struct sqlite_prepared_statement *prep_stmt =
		container_of(_prep_stmt, struct sqlite_prepared_statement, api);
	if (prep_stmt->handle != NULL) {
		driver_sqlite_finalize_handle(prep_stmt->api.db, &prep_stmt->handle,
					      prep_stmt->api.query_template);
	}
	i_free(prep_stmt->api.query_template);
	i_free(prep_stmt->error);
	i_free(_prep_stmt);
}

static void
driver_sqlite_bind_error(const char *func, struct sqlite_statement *stmt,
			 unsigned int column_idx)
{
	const char *errstr = driver_sqlite_result_str(stmt->api.db, stmt->rc);
	if (stmt->rc == SQLITE_NOMEM) {
		i_fatal_status(FATAL_OUTOFMEM, "%s(%u) for query '%s': %s",
			       func, column_idx, stmt->api.query_template,
			       errstr);
	} else if (stmt->rc != SQLITE_OK) {
		stmt->error = p_strdup_printf(stmt->api.pool, "%s(%u) for query '%s': %s",
			func, column_idx, stmt->api.query_template,
			errstr);
	}
}

static void
driver_sqlite_statement_bind_str(struct sql_statement *_stmt,
				 unsigned int column_idx, const char *value)
{
	struct sqlite_statement *stmt =
		container_of(_stmt, struct sqlite_statement, api);
	if (stmt->rc != SQLITE_OK)
		return;
	stmt->rc = sqlite3_bind_text(stmt->handle, column_idx + 1, value, -1,
				     SQLITE_TRANSIENT);
	driver_sqlite_bind_error("sqlite3_bind_text", stmt, column_idx);
}

static void
driver_sqlite_statement_bind_binary(struct sql_statement *_stmt,
				    unsigned int column_idx, const void *value,
				    size_t value_size)
{
	struct sqlite_statement *stmt =
		container_of(_stmt, struct sqlite_statement, api);
	if (stmt->rc != SQLITE_OK)
		return;
	stmt->rc = sqlite3_bind_blob(stmt->handle, column_idx + 1, value,
				     value_size, SQLITE_TRANSIENT);
	driver_sqlite_bind_error("sqlite3_bind_blob", stmt, column_idx);
}

static void
driver_sqlite_statement_bind_int64(struct sql_statement *_stmt,
				   unsigned int column_idx, int64_t value)
{
	struct sqlite_statement *stmt =
		container_of(_stmt, struct sqlite_statement, api);
	if (stmt->rc != SQLITE_OK)
		return;
	stmt->rc = sqlite3_bind_int64(stmt->handle, column_idx + 1, value);
	driver_sqlite_bind_error("sqlite3_bind_int64", stmt, column_idx);
}

static void
driver_sqlite_statement_bind_double(struct sql_statement *_stmt,
				    unsigned int column_idx, double value)
{
	struct sqlite_statement *stmt =
		container_of(_stmt, struct sqlite_statement, api);
	if (stmt->rc != SQLITE_OK)
		return;
	stmt->rc = sqlite3_bind_double(stmt->handle, column_idx + 1, value);
	driver_sqlite_bind_error("sqlite3_bind_double", stmt, column_idx);
}

static void
driver_sqlite_statement_bind_uuid(struct sql_statement *stmt,
				  unsigned int column_idx, const guid_128_t uuid)

{
	const char *uuid_str = guid_128_to_uuid_string(uuid, FORMAT_RECORD);
	driver_sqlite_statement_bind_str(stmt, column_idx, uuid_str);
}

static void
driver_sqlite_update_stmt(struct sql_transaction_context *_ctx,
			  struct sql_statement *_stmt,
			  unsigned int *affected_rows)
{
	struct sqlite_transaction_context *ctx =
		container_of(_ctx, struct sqlite_transaction_context, ctx);
	struct sqlite_db *db =
		container_of(_ctx->db, struct sqlite_db, api);
	struct sqlite_statement *stmt =
		container_of(_stmt, struct sqlite_statement, api);
	/* execute statement */
	struct sql_result *_res = driver_sqlite_statement_query_s(&stmt->api);
	struct sqlite_result *res =
		container_of(_res, struct sqlite_result, api);
	if (sql_result_next_row(_res) < 0) {
		ctx->rc = res->rc;
		i_free(ctx->error);
		ctx->error = i_strdup(driver_sqlite_result_str(stmt->api.db, ctx->rc));
		if (affected_rows != NULL)
			*affected_rows = 0;
	} else if (SQLITE_IS_OK(res->rc) && affected_rows != NULL)
		*affected_rows = sqlite3_changes(db->sqlite);

	sql_result_unref(_res);
}

const struct sql_db driver_sqlite_db = {
	.name = "sqlite",
	.flags =
#if SQLITE_VERSION_NUMBER >= 3024000
		SQL_DB_FLAG_ON_CONFLICT_DO |
#endif
		SQL_DB_FLAG_BLOCKING,

	.v = {
		.init = driver_sqlite_init_v,
		.deinit = driver_sqlite_deinit_v,
		.connect = driver_sqlite_connect,
		.disconnect = driver_sqlite_disconnect,
		.escape_string = driver_sqlite_escape_string,
		.exec = driver_sqlite_exec,
		.query_s = driver_sqlite_query_s,

		.transaction_begin = driver_sqlite_transaction_begin,
		.transaction_commit_s = driver_sqlite_transaction_commit_s,
		.transaction_rollback = driver_sqlite_transaction_rollback,

		.update = driver_sqlite_update,

		.escape_blob = driver_sqlite_escape_blob,

		.prepared_statement_init = driver_sqlite_prepared_statement_init,
		.prepared_statement_deinit = driver_sqlite_prepared_statement_deinit,

		.statement_init = driver_sqlite_statement_init,
		.statement_init_prepared = driver_sqlite_statement_init_prepared,
		.statement_abort = driver_sqlite_statement_abort,

		.statement_bind_str = driver_sqlite_statement_bind_str,
		.statement_bind_binary = driver_sqlite_statement_bind_binary,
		.statement_bind_int64 = driver_sqlite_statement_bind_int64,
		.statement_bind_double = driver_sqlite_statement_bind_double,
		.statement_bind_uuid = driver_sqlite_statement_bind_uuid,

		.statement_query_s = driver_sqlite_statement_query_s,

		.update_stmt = driver_sqlite_update_stmt,

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

void driver_sqlite_init(void)
{
	i_array_init(&sqlite_db_cache, 4);
	sql_driver_register(&driver_sqlite_db);
	int rc = sqlite3_initialize();
	if (rc != SQLITE_OK)
		i_fatal("Cannot initialize sqlite: %s", sqlite3_errstr(rc));
}

void driver_sqlite_deinit(void)
{
	struct sqlite_db *db;

	array_foreach_elem(&sqlite_db_cache, db) {
		struct sql_db *_db = &db->api;
		sql_unref(&_db);
	}
	array_free(&sqlite_db_cache);
	sql_driver_unregister(&driver_sqlite_db);
	sqlite3_shutdown();
}

#endif
