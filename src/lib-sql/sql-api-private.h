#ifndef SQL_API_PRIVATE_H
#define SQL_API_PRIVATE_H

#include "sql-api.h"
#include "module-context.h"

struct sql_db_module_register {
	unsigned int id;
};

union sql_db_module_context {
	struct sql_db_module_register *reg;
};

extern struct sql_db_module_register sql_db_module_register;

struct sql_db_vfuncs {
	struct sql_db *(*init)(const char *connect_string);
	void (*deinit)(struct sql_db *db);

	enum sql_db_flags (*get_flags)(struct sql_db *db);

	int (*connect)(struct sql_db *db);
	const char *(*escape_string)(struct sql_db *db, const char *string);
	void (*exec)(struct sql_db *db, const char *query);
	void (*query)(struct sql_db *db, const char *query,
		      sql_query_callback_t *callback, void *context);
	struct sql_result *(*query_s)(struct sql_db *db, const char *query);

	struct sql_transaction_context *(*transaction_begin)(struct sql_db *db);
	void (*transaction_commit)(struct sql_transaction_context *ctx,
				   sql_commit_callback_t *callback,
				   void *context);
	int (*transaction_commit_s)(struct sql_transaction_context *ctx,
				    const char **error_r);
	void (*transaction_rollback)(struct sql_transaction_context *ctx);

	void (*update)(struct sql_transaction_context *ctx, const char *query,
		       unsigned int *affected_rows);
};

struct sql_db {
	const char *name;
	struct sql_db_vfuncs v;
	ARRAY_DEFINE(module_contexts, union sql_db_module_context *);
};

struct sql_result_vfuncs {
	void (*free)(struct sql_result *result);
	int (*next_row)(struct sql_result *result);

	unsigned int (*get_fields_count)(struct sql_result *result);
	const char *(*get_field_name)(struct sql_result *result,
				      unsigned int idx);
	int (*find_field)(struct sql_result *result, const char *field_name);

	const char *(*get_field_value)(struct sql_result *result,
				       unsigned int idx);
	const unsigned char *
		(*get_field_value_binary)(struct sql_result *result,
					  unsigned int idx,
					  size_t *size_r);
	const char *(*find_field_value)(struct sql_result *result,
					const char *field_name);
	const char *const *(*get_values)(struct sql_result *result);

	const char *(*get_error)(struct sql_result *result);
};

struct sql_field_map {
	enum sql_field_type type;
	size_t offset;
};

struct sql_result {
	struct sql_result_vfuncs v;
	int refcount;

	struct sql_db *db;
	const struct sql_field_def *fields;

	unsigned int map_size;
	struct sql_field_map *map;
	void *fetch_dest;
	size_t fetch_dest_size;

	unsigned int callback:1;
};

struct sql_transaction_context {
	struct sql_db *db;
};

ARRAY_DEFINE_TYPE(sql_drivers, const struct sql_db *);

extern ARRAY_TYPE(sql_drivers) sql_drivers;
extern struct sql_result sql_not_connected_result;

#endif
