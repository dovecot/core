/* Copyright (c) 2004-2006 Timo Sirainen */

#include "lib.h"
#include "array.h"
#include "sql-api-private.h"

array_t ARRAY_DEFINE(sql_drivers, const struct sql_db *);

void sql_drivers_init(void)
{
	ARRAY_CREATE(&sql_drivers, default_pool, const struct sql_db *, 8);
}

void sql_drivers_deinit(void)
{
	array_free(&sql_drivers);
}

void sql_driver_register(const struct sql_db *driver)
{
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

struct sql_db *sql_init(const char *db_driver,
			const char *connect_string __attr_unused__)
{
	const struct sql_db *const *drivers;
	unsigned int i, count;

	drivers = array_get(&sql_drivers, &count);
	for (i = 0; i < count; i++) {
		if (strcmp(db_driver, drivers[i]->name) == 0)
			return drivers[i]->init(connect_string);
	}

	i_fatal("Unknown database driver '%s'", db_driver);
}

void sql_deinit(struct sql_db **db)
{
	(*db)->deinit(*db);
	*db = NULL;
}

enum sql_db_flags sql_get_flags(struct sql_db *db)
{
	return db->get_flags(db);
}

int sql_connect(struct sql_db *db)
{
	return db->connect(db);
}

void sql_exec(struct sql_db *db, const char *query)
{
	db->exec(db, query);
}

void sql_query(struct sql_db *db, const char *query,
	       sql_query_callback_t *callback, void *context)
{
	db->query(db, query, callback, context);
}

struct sql_result *sql_query_s(struct sql_db *db, const char *query)
{
	return db->query_s(db, query);
}

void sql_result_free(struct sql_result *result)
{
	result->free(result);
}

int sql_result_next_row(struct sql_result *result)
{
	return result->next_row(result);
}

unsigned int sql_result_get_fields_count(struct sql_result *result)
{
	return result->get_fields_count(result);
}

const char *sql_result_get_field_name(struct sql_result *result,
				      unsigned int idx)
{
	return result->get_field_name(result, idx);
}

int sql_result_find_field(struct sql_result *result, const char *field_name)
{
	return result->find_field(result, field_name);
}

const char *sql_result_get_field_value(struct sql_result *result,
				       unsigned int idx)
{
	return result->get_field_value(result, idx);
}

const char *sql_result_find_field_value(struct sql_result *result,
					const char *field_name)
{
	return result->find_field_value(result, field_name);
}

const char *const *sql_result_get_values(struct sql_result *result)
{
	return result->get_values(result);
}

const char *sql_result_get_error(struct sql_result *result)
{
	return result->get_error(result);
}

static void
sql_result_not_connected_free(struct sql_result *result __attr_unused__)
{
}

static int
sql_result_not_connected_next_row(struct sql_result *result __attr_unused__)
{
	return -1;
}

static const char *
sql_result_not_connected_get_error(struct sql_result *result __attr_unused__)
{
	return "Not connected to database";
}

struct sql_transaction_context *sql_transaction_begin(struct sql_db *db)
{
	return db->transaction_begin(db);
}

void sql_transaction_commit(struct sql_transaction_context **_ctx,
			    sql_commit_callback_t *callback, void *context)
{
	struct sql_transaction_context *ctx = *_ctx;

	*_ctx = NULL;
	ctx->db->transaction_commit(ctx, callback, context);
}

int sql_transaction_commit_s(struct sql_transaction_context **_ctx,
			     const char **error_r)
{
	struct sql_transaction_context *ctx = *_ctx;

	*_ctx = NULL;
	return ctx->db->transaction_commit_s(ctx, error_r);
}

void sql_transaction_rollback(struct sql_transaction_context **_ctx)
{
	struct sql_transaction_context *ctx = *_ctx;

	*_ctx = NULL;
	ctx->db->transaction_rollback(ctx);
}

void sql_update(struct sql_transaction_context *ctx, const char *query)
{
	ctx->db->update(ctx, query);
}

struct sql_result sql_not_connected_result = {
	NULL,

	sql_result_not_connected_free,
	sql_result_not_connected_next_row,
	NULL, NULL, NULL, NULL, NULL, NULL,
	sql_result_not_connected_get_error,

	FALSE
};
