/* Copyright (c) 2004-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "hash.h"
#include "str.h"
#include "time-util.h"
#include "sql-api-private.h"

#include <time.h>

struct event_category event_category_sql = {
	.name = "sql",
};

struct sql_db_module_register sql_db_module_register = { 0 };
ARRAY_TYPE(sql_drivers) sql_drivers;

void sql_drivers_init(void)
{
	i_array_init(&sql_drivers, 8);
}

void sql_drivers_deinit(void)
{
	array_free(&sql_drivers);
}

static const struct sql_db *sql_driver_lookup(const char *name)
{
	const struct sql_db *const *drivers;
	unsigned int i, count;

	drivers = array_get(&sql_drivers, &count);
	for (i = 0; i < count; i++) {
		if (strcmp(drivers[i]->name, name) == 0)
			return drivers[i];
	}
	return NULL;
}

void sql_driver_register(const struct sql_db *driver)
{
	if (sql_driver_lookup(driver->name) != NULL) {
		i_fatal("sql_driver_register(%s): Already registered",
			driver->name);
	}
	array_push_back(&sql_drivers, &driver);
}

void sql_driver_unregister(const struct sql_db *driver)
{
	const struct sql_db *const *drivers;
	unsigned int i, count;

	drivers = array_get(&sql_drivers, &count);
	for (i = 0; i < count; i++) {
		if (drivers[i] == driver) {
			array_delete(&sql_drivers, i, 1);
			break;
		}
	}
}

struct sql_db *sql_init(const char *db_driver, const char *connect_string)
{
	const char *error;
	struct sql_db *db;
	struct sql_settings set = {
		.driver = db_driver,
		.connect_string = connect_string,
	};

	if (sql_init_full(&set, &db, &error) < 0)
		i_fatal("%s", error);
	return db;
}

int sql_init_full(const struct sql_settings *set, struct sql_db **db_r,
		  const char **error_r)
{
	const struct sql_db *driver;
	struct sql_db *db;
	int ret = 0;

	i_assert(set->connect_string != NULL);

	driver = sql_driver_lookup(set->driver);
	if (driver == NULL) {
		*error_r = t_strdup_printf("Unknown database driver '%s'", set->driver);
		return -1;
	}

	if ((driver->flags & SQL_DB_FLAG_POOLED) == 0) {
		if (driver->v.init_full == NULL) {
			db = driver->v.init(set->connect_string);
		} else
			ret = driver->v.init_full(set, &db, error_r);
	} else
		ret = driver_sqlpool_init_full(set, driver, &db, error_r);

	if (ret < 0)
		return -1;

	i_array_init(&db->module_contexts, 5);
	db->refcount = 1;
	hash_table_create(&db->prepared_stmt_hash, default_pool, 0,
			  str_hash, strcmp);
	*db_r = db;
	return 0;
}

void sql_ref(struct sql_db *db)
{
	db->refcount++;
}

void sql_unref(struct sql_db **_db)
{
	struct sql_db *db = *_db;

	*_db = NULL;

	if (db->v.unref != NULL)
		db->v.unref(db);
	if (--db->refcount > 0)
		return;

	timeout_remove(&db->to_reconnect);
	i_assert(hash_table_count(db->prepared_stmt_hash) == 0);
	hash_table_destroy(&db->prepared_stmt_hash);
	db->v.deinit(db);
}

enum sql_db_flags sql_get_flags(struct sql_db *db)
{
	return db->flags;
}

int sql_connect(struct sql_db *db)
{
	time_t now;

	switch (db->state) {
	case SQL_DB_STATE_DISCONNECTED:
		break;
	case SQL_DB_STATE_CONNECTING:
		return 0;
	default:
		return 1;
	}

	/* don't try reconnecting more than once a second */
	now = time(NULL);
	if (db->last_connect_try + (time_t)db->connect_delay > now)
		return -1;
	db->last_connect_try = now;

	return db->v.connect(db);
}

void sql_disconnect(struct sql_db *db)
{
	timeout_remove(&db->to_reconnect);
	db->v.disconnect(db);
}

const char *sql_escape_string(struct sql_db *db, const char *string)
{
	return db->v.escape_string(db, string);
}

const char *sql_escape_blob(struct sql_db *db,
			    const unsigned char *data, size_t size)
{
	return db->v.escape_blob(db, data, size);
}

void sql_exec(struct sql_db *db, const char *query)
{
	db->v.exec(db, query);
}

#undef sql_query
void sql_query(struct sql_db *db, const char *query,
	       sql_query_callback_t *callback, void *context)
{
	db->v.query(db, query, callback, context);
}

struct sql_result *sql_query_s(struct sql_db *db, const char *query)
{
	return db->v.query_s(db, query);
}

static struct sql_prepared_statement *
default_sql_prepared_statement_init(struct sql_db *db,
				    const char *query_template)
{
	struct sql_prepared_statement *prep_stmt;

	prep_stmt = i_new(struct sql_prepared_statement, 1);
	prep_stmt->db = db;
	prep_stmt->refcount = 1;
	prep_stmt->query_template = i_strdup(query_template);
	return prep_stmt;
}

static void
default_sql_prepared_statement_deinit(struct sql_prepared_statement *prep_stmt)
{
	i_free(prep_stmt->query_template);
	i_free(prep_stmt);
}

static struct sql_statement *
default_sql_statement_init_prepared(struct sql_prepared_statement *stmt)
{
	return sql_statement_init(stmt->db, stmt->query_template);
}

const char *sql_statement_get_query(struct sql_statement *stmt)
{
	string_t *query = t_str_new(128);
	const char *const *args;
	unsigned int i, args_count, arg_pos = 0;

	args = array_get(&stmt->args, &args_count);

	for (i = 0; stmt->query_template[i] != '\0'; i++) {
		if (stmt->query_template[i] == '?') {
			if (arg_pos >= args_count ||
			    args[arg_pos] == NULL) {
				i_panic("lib-sql: Missing bind for arg #%u in statement: %s",
					arg_pos, stmt->query_template);
			}
			str_append(query, args[arg_pos++]);
		} else {
			str_append_c(query, stmt->query_template[i]);
		}
	}
	if (arg_pos != args_count) {
		i_panic("lib-sql: Too many bind args (%u) for statement: %s",
			args_count, stmt->query_template);
	}
	return str_c(query);
}

static void
default_sql_statement_query(struct sql_statement *stmt,
			    sql_query_callback_t *callback, void *context)
{
	sql_query(stmt->db, sql_statement_get_query(stmt),
		  callback, context);
	pool_unref(&stmt->pool);
}

static struct sql_result *
default_sql_statement_query_s(struct sql_statement *stmt)
{
	struct sql_result *result =
		sql_query_s(stmt->db, sql_statement_get_query(stmt));
	pool_unref(&stmt->pool);
	return result;
}

static void default_sql_update_stmt(struct sql_transaction_context *ctx,
				    struct sql_statement *stmt,
				    unsigned int *affected_rows)
{
	ctx->db->v.update(ctx, sql_statement_get_query(stmt),
			  affected_rows);
	pool_unref(&stmt->pool);
}

struct sql_prepared_statement *
sql_prepared_statement_init(struct sql_db *db, const char *query_template)
{
	struct sql_prepared_statement *stmt;

	stmt = hash_table_lookup(db->prepared_stmt_hash, query_template);
	if (stmt != NULL) {
		stmt->refcount++;
		return stmt;
	}

	if (db->v.prepared_statement_init != NULL)
		stmt = db->v.prepared_statement_init(db, query_template);
	else
		stmt = default_sql_prepared_statement_init(db, query_template);

	hash_table_insert(db->prepared_stmt_hash, stmt->query_template, stmt);
	return stmt;
}

void sql_prepared_statement_deinit(struct sql_prepared_statement **_prep_stmt)
{
	struct sql_prepared_statement *prep_stmt = *_prep_stmt;

	*_prep_stmt = NULL;

	i_assert(prep_stmt->refcount > 0);
	if (--prep_stmt->refcount > 0)
		return;

	if (prep_stmt->db->v.prepared_statement_deinit != NULL)
		prep_stmt->db->v.prepared_statement_deinit(prep_stmt);
	else
		default_sql_prepared_statement_deinit(prep_stmt);
}

static void
sql_statement_init_fields(struct sql_statement *stmt, struct sql_db *db)
{
	stmt->db = db;
	p_array_init(&stmt->args, stmt->pool, 8);
}

struct sql_statement *
sql_statement_init(struct sql_db *db, const char *query_template)
{
	struct sql_statement *stmt;

	if (db->v.statement_init != NULL)
		stmt = db->v.statement_init(db, query_template);
	else {
		pool_t pool = pool_alloconly_create("sql statement", 1024);
		stmt = p_new(pool, struct sql_statement, 1);
		stmt->pool = pool;
	}
	stmt->query_template = p_strdup(stmt->pool, query_template);
	sql_statement_init_fields(stmt, db);
	return stmt;
}

struct sql_statement *
sql_statement_init_prepared(struct sql_prepared_statement *prep_stmt)
{
	struct sql_statement *stmt;

	if (prep_stmt->db->v.statement_init_prepared == NULL)
		return default_sql_statement_init_prepared(prep_stmt);

	stmt = prep_stmt->db->v.statement_init_prepared(prep_stmt);
	sql_statement_init_fields(stmt, prep_stmt->db);
	return stmt;
}

void sql_statement_abort(struct sql_statement **_stmt)
{
	struct sql_statement *stmt = *_stmt;

	*_stmt = NULL;
	if (stmt->db->v.statement_abort != NULL)
		stmt->db->v.statement_abort(stmt);
	pool_unref(&stmt->pool);
}

void sql_statement_set_timestamp(struct sql_statement *stmt,
				 const struct timespec *ts)
{
	if (stmt->db->v.statement_set_timestamp != NULL)
		stmt->db->v.statement_set_timestamp(stmt, ts);
}

void sql_statement_bind_str(struct sql_statement *stmt,
			    unsigned int column_idx, const char *value)
{
	const char *escaped_value =
		p_strdup_printf(stmt->pool, "'%s'",
				sql_escape_string(stmt->db, value));
	array_idx_set(&stmt->args, column_idx, &escaped_value);

	if (stmt->db->v.statement_bind_str != NULL)
		stmt->db->v.statement_bind_str(stmt, column_idx, value);
}

void sql_statement_bind_binary(struct sql_statement *stmt,
			       unsigned int column_idx, const void *value,
			       size_t value_size)
{
	const char *value_str =
		p_strdup_printf(stmt->pool, "%s",
				sql_escape_blob(stmt->db, value, value_size));
	array_idx_set(&stmt->args, column_idx, &value_str);

	if (stmt->db->v.statement_bind_binary != NULL) {
		stmt->db->v.statement_bind_binary(stmt, column_idx,
						  value, value_size);
	}
}

void sql_statement_bind_int64(struct sql_statement *stmt,
			      unsigned int column_idx, int64_t value)
{
	const char *value_str = p_strdup_printf(stmt->pool, "%"PRId64, value);
	array_idx_set(&stmt->args, column_idx, &value_str);

	if (stmt->db->v.statement_bind_int64 != NULL)
		stmt->db->v.statement_bind_int64(stmt, column_idx, value);
}

#undef sql_statement_query
void sql_statement_query(struct sql_statement **_stmt,
			 sql_query_callback_t *callback, void *context)
{
	struct sql_statement *stmt = *_stmt;

	*_stmt = NULL;
	if (stmt->db->v.statement_query != NULL)
		stmt->db->v.statement_query(stmt, callback, context);
	else
		default_sql_statement_query(stmt, callback, context);
}

struct sql_result *sql_statement_query_s(struct sql_statement **_stmt)
{
	struct sql_statement *stmt = *_stmt;

	*_stmt = NULL;
	if (stmt->db->v.statement_query_s != NULL)
		return stmt->db->v.statement_query_s(stmt);
	else
		return default_sql_statement_query_s(stmt);
}

void sql_result_ref(struct sql_result *result)
{
	result->refcount++;
}

void sql_result_unref(struct sql_result *result)
{
	i_assert(result->refcount > 0);
	if (--result->refcount > 0)
		return;

	i_free(result->map);
	result->v.free(result);
}

static const struct sql_field_def *
sql_field_def_find(const struct sql_field_def *fields, const char *name)
{
	unsigned int i;

	for (i = 0; fields[i].name != NULL; i++) {
		if (strcasecmp(fields[i].name, name) == 0)
			return &fields[i];
	}
	return NULL;
}

static void
sql_result_build_map(struct sql_result *result,
		     const struct sql_field_def *fields, size_t dest_size)
{
	const struct sql_field_def *def;
	const char *name;
	unsigned int i, count, field_size = 0;

	count = sql_result_get_fields_count(result);

	result->map_size = count;
	result->map = i_new(struct sql_field_map, result->map_size);
	for (i = 0; i < count; i++) {
		name = sql_result_get_field_name(result, i);
		def = sql_field_def_find(fields, name);
		if (def != NULL) {
			result->map[i].type = def->type;
			result->map[i].offset = def->offset;
			switch (def->type) {
			case SQL_TYPE_STR:
				field_size = sizeof(const char *);
				break;
			case SQL_TYPE_UINT:
				field_size = sizeof(unsigned int);
				break;
			case SQL_TYPE_ULLONG:
				field_size = sizeof(unsigned long long);
				break;
			case SQL_TYPE_BOOL:
				field_size = sizeof(bool);
				break;
			}
			i_assert(def->offset + field_size <= dest_size);
		} else {
			result->map[i].offset = (size_t)-1;
		}
	}
}

void sql_result_setup_fetch(struct sql_result *result,
			    const struct sql_field_def *fields,
			    void *dest, size_t dest_size)
{
	if (result->map == NULL)
		sql_result_build_map(result, fields, dest_size);
	result->fetch_dest = dest;
	result->fetch_dest_size = dest_size;
}

static void sql_result_fetch(struct sql_result *result)
{
	unsigned int i, count;
	const char *value;
	void *ptr;

	memset(result->fetch_dest, 0, result->fetch_dest_size);
	count = result->map_size;
	for (i = 0; i < count; i++) {
		if (result->map[i].offset == (size_t)-1)
			continue;

		value = sql_result_get_field_value(result, i);
		ptr = STRUCT_MEMBER_P(result->fetch_dest,
				      result->map[i].offset);

		switch (result->map[i].type) {
		case SQL_TYPE_STR: {
			*((const char **)ptr) = value;
			break;
		}
		case SQL_TYPE_UINT: {
			if (value != NULL &&
			    str_to_uint(value, (unsigned int *)ptr) < 0)
				i_error("sql: Value not uint: %s", value);
			break;
		}
		case SQL_TYPE_ULLONG: {
			if (value != NULL &&
			    str_to_ullong(value, (unsigned long long *)ptr) < 0)
				i_error("sql: Value not ullong: %s", value);
			break;
		}
		case SQL_TYPE_BOOL: {
			if (value != NULL && (*value == 't' || *value == '1'))
				*((bool *)ptr) = TRUE;
			break;
		}
		}
	}
}

int sql_result_next_row(struct sql_result *result)
{
	int ret;

	if ((ret = result->v.next_row(result)) <= 0)
		return ret;

	if (result->fetch_dest != NULL)
		sql_result_fetch(result);
	return 1;
}

#undef sql_result_more
void sql_result_more(struct sql_result **result,
		     sql_query_callback_t *callback, void *context)
{
	i_assert((*result)->v.more != NULL);

	(*result)->v.more(result, TRUE, callback, context);
}

static void
sql_result_more_sync_callback(struct sql_result *result, void *context)
{
	struct sql_result **dest_result = context;

	*dest_result = result;
}

void sql_result_more_s(struct sql_result **result)
{
	i_assert((*result)->v.more != NULL);

	(*result)->v.more(result, FALSE, sql_result_more_sync_callback, result);
	/* the callback must have been called */
	i_assert(*result != NULL);
}

unsigned int sql_result_get_fields_count(struct sql_result *result)
{
	return result->v.get_fields_count(result);
}

const char *sql_result_get_field_name(struct sql_result *result,
				      unsigned int idx)
{
	return result->v.get_field_name(result, idx);
}

int sql_result_find_field(struct sql_result *result, const char *field_name)
{
	return result->v.find_field(result, field_name);
}

const char *sql_result_get_field_value(struct sql_result *result,
				       unsigned int idx)
{
	return result->v.get_field_value(result, idx);
}

const unsigned char *
sql_result_get_field_value_binary(struct sql_result *result,
				  unsigned int idx, size_t *size_r)
{
	return result->v.get_field_value_binary(result, idx, size_r);
}

const char *sql_result_find_field_value(struct sql_result *result,
					const char *field_name)
{
	return result->v.find_field_value(result, field_name);
}

const char *const *sql_result_get_values(struct sql_result *result)
{
	return result->v.get_values(result);
}

const char *sql_result_get_error(struct sql_result *result)
{
	return result->v.get_error(result);
}

enum sql_result_error_type sql_result_get_error_type(struct sql_result *result)
{
	return result->error_type;
}

static void
sql_result_not_connected_free(struct sql_result *result ATTR_UNUSED)
{
}

static int
sql_result_not_connected_next_row(struct sql_result *result ATTR_UNUSED)
{
	return -1;
}

static const char *
sql_result_not_connected_get_error(struct sql_result *result ATTR_UNUSED)
{
	return SQL_ERRSTR_NOT_CONNECTED;
}

struct sql_transaction_context *sql_transaction_begin(struct sql_db *db)
{
	return db->v.transaction_begin(db);
}

#undef sql_transaction_commit
void sql_transaction_commit(struct sql_transaction_context **_ctx,
			    sql_commit_callback_t *callback, void *context)
{
	struct sql_transaction_context *ctx = *_ctx;

	*_ctx = NULL;
	ctx->db->v.transaction_commit(ctx, callback, context);
}

int sql_transaction_commit_s(struct sql_transaction_context **_ctx,
			     const char **error_r)
{
	struct sql_transaction_context *ctx = *_ctx;

	*_ctx = NULL;
	return ctx->db->v.transaction_commit_s(ctx, error_r);
}

void sql_transaction_rollback(struct sql_transaction_context **_ctx)
{
	struct sql_transaction_context *ctx = *_ctx;

	*_ctx = NULL;
	ctx->db->v.transaction_rollback(ctx);
}

void sql_update(struct sql_transaction_context *ctx, const char *query)
{
	ctx->db->v.update(ctx, query, NULL);
}

void sql_update_stmt(struct sql_transaction_context *ctx,
		     struct sql_statement **_stmt)
{
	struct sql_statement *stmt = *_stmt;

	*_stmt = NULL;
	if (ctx->db->v.update_stmt != NULL)
		ctx->db->v.update_stmt(ctx, stmt, NULL);
	else
		default_sql_update_stmt(ctx, stmt, NULL);
}

void sql_update_get_rows(struct sql_transaction_context *ctx, const char *query,
			 unsigned int *affected_rows)
{
	ctx->db->v.update(ctx, query, affected_rows);
}

void sql_update_stmt_get_rows(struct sql_transaction_context *ctx,
			      struct sql_statement **_stmt,
			      unsigned int *affected_rows)
{
	struct sql_statement *stmt = *_stmt;

	*_stmt = NULL;
	if (ctx->db->v.update_stmt != NULL)
		ctx->db->v.update_stmt(ctx, stmt, affected_rows);
	else
		default_sql_update_stmt(ctx, stmt, affected_rows);
}

void sql_db_set_state(struct sql_db *db, enum sql_db_state state)
{
	enum sql_db_state old_state = db->state;

	if (db->state == state)
		return;

	db->state = state;
	if (db->state_change_callback != NULL) {
		db->state_change_callback(db, old_state,
					  db->state_change_context);
	}
}

void sql_transaction_add_query(struct sql_transaction_context *ctx, pool_t pool,
			       const char *query, unsigned int *affected_rows)
{
	struct sql_transaction_query *tquery;

	tquery = p_new(pool, struct sql_transaction_query, 1);
	tquery->trans = ctx;
	tquery->query = p_strdup(pool, query);
	tquery->affected_rows = affected_rows;

	if (ctx->head == NULL)
		ctx->head = tquery;
	else
		ctx->tail->next = tquery;
	ctx->tail = tquery;
}

void sql_connection_log_finished(struct sql_db *db)
{
	struct event_passthrough *e = event_create_passthrough(db->event)->
		set_name(SQL_CONNECTION_FINISHED);
	e_debug(e->event(),
		"Connection finished (queries=%"PRIu64", slow queries=%"PRIu64")",
		db->succeeded_queries + db->failed_queries,
		db->slow_queries);
}

struct event_passthrough *
sql_query_finished_event(struct sql_db *db, struct event *event, const char *query,
			 bool success, int *duration_r)
{
	int diff;
	struct timeval tv;
	event_get_create_time(event, &tv);
	struct event_passthrough *e = event_create_passthrough(event)->
			set_name(SQL_QUERY_FINISHED)->
			add_str("query_first_word", t_strcut(query, ' '));
	diff = timeval_diff_msecs(&ioloop_timeval, &tv);

	if (!success) {
		db->failed_queries++;
	} else {
		db->succeeded_queries++;
	}

	if (diff >= SQL_SLOW_QUERY_MSEC) {
		e->add_str("slow_query", "y");
		db->slow_queries++;
	}

	if (duration_r != NULL)
		*duration_r = diff;

	return e;
}

struct event_passthrough *sql_transaction_finished_event(struct sql_transaction_context *ctx)
{
	return event_create_passthrough(ctx->event)->
		set_name(SQL_TRANSACTION_FINISHED);
}

struct sql_result sql_not_connected_result = {
	.v = {
		sql_result_not_connected_free,
		sql_result_not_connected_next_row,
		NULL, NULL, NULL, NULL, NULL, NULL, NULL,
		sql_result_not_connected_get_error,
		NULL,
	},
	.failed_try_retry = TRUE
};
