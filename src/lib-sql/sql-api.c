/* Copyright (c) 2004-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "sql-api-private.h"

#include <stdlib.h>
#include <time.h>

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
	array_append(&sql_drivers, &driver, 1);
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
	const struct sql_db *driver;
	struct sql_db *db;

	i_assert(connect_string != NULL);

	driver = sql_driver_lookup(db_driver);
	if (driver == NULL)
		i_fatal("Unknown database driver '%s'", db_driver);

	if ((driver->flags & SQL_DB_FLAG_POOLED) == 0)
		db = driver->v.init(connect_string);
	else
		db = driver_sqlpool_init(connect_string, driver);
	i_array_init(&db->module_contexts, 5);
	return db;
}

void sql_deinit(struct sql_db **_db)
{
	struct sql_db *db = *_db;

	*_db = NULL;

	if (db->to_reconnect != NULL)
		timeout_remove(&db->to_reconnect);
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
	if (db->to_reconnect != NULL)
		timeout_remove(&db->to_reconnect);
	db->v.disconnect(db);
}

const char *sql_escape_string(struct sql_db *db, const char *string)
{
	return db->v.escape_string(db, string);
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
	sql_update_get_rows(ctx, query, NULL);
}

void sql_update_get_rows(struct sql_transaction_context *ctx, const char *query,
			 unsigned int *affected_rows)
{
	ctx->db->v.update(ctx, query, affected_rows);
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

struct sql_result sql_not_connected_result = {
	.v = {
		sql_result_not_connected_free,
		sql_result_not_connected_next_row,
		NULL, NULL, NULL, NULL, NULL, NULL, NULL,
		sql_result_not_connected_get_error
	},
	.failed_try_retry = TRUE
};
