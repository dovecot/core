/* Copyright (c) 2004 Timo Sirainen */

#include "lib.h"
#include "sql-api-private.h"

struct sql_db *sql_init(const char *db_driver, const char *connect_string)
{
#ifdef HAVE_PGSQL
	if (strcmp(db_driver, "pgsql") == 0)
		return driver_pgsql_db.init(connect_string);
#endif
#ifdef HAVE_MYSQL
	if (strcmp(db_driver, "mysql") == 0)
		return driver_mysql_db.init(connect_string);
#endif

	i_fatal("Unknown database driver '%s'", db_driver);
}

void sql_deinit(struct sql_db *db)
{
	db->deinit(db);
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

struct sql_result sql_not_connected_result = {
	NULL,

	sql_result_not_connected_next_row,
	NULL, NULL, NULL, NULL, NULL, NULL,
	sql_result_not_connected_get_error
};
