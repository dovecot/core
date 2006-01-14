/* Copyright (C) 2004 Timo Sirainen, Alex Howansky */

#include "common.h"

#ifdef PASSDB_SQL

#include "str.h"
#include "strescape.h"
#include "var-expand.h"
#include "password-scheme.h"
#include "auth-cache.h"
#include "db-sql.h"
#include "passdb.h"

#include <stdlib.h>
#include <string.h>

struct sql_passdb_module {
	struct passdb_module module;

	struct sql_connection *conn;
};

struct passdb_sql_request {
	struct auth_request *auth_request;
	union {
		verify_plain_callback_t *verify_plain;
                lookup_credentials_callback_t *lookup_credentials;
	} callback;
};

static void sql_query_save_results(struct sql_result *result,
				   struct passdb_sql_request *sql_request)
{
	struct auth_request *auth_request = sql_request->auth_request;
	struct passdb_module *_module = auth_request->passdb->passdb;
	struct sql_passdb_module *module = (struct sql_passdb_module *)_module;
	unsigned int i, fields_count;
	const char *name, *value;

        fields_count = sql_result_get_fields_count(result);
	for (i = 0; i < fields_count; i++) {
		name = sql_result_get_field_name(result, i);
		value = sql_result_get_field_value(result, i);

		if (value != NULL) {
			auth_request_set_field(auth_request, name, value,
				module->conn->set.default_pass_scheme);
		}
	}
}

static void sql_query_callback(struct sql_result *result, void *context)
{
	struct passdb_sql_request *sql_request = context;
	struct auth_request *auth_request = sql_request->auth_request;
	enum passdb_result passdb_result;
	const char *user, *password, *scheme;
	int ret;

	passdb_result = PASSDB_RESULT_INTERNAL_FAILURE;
	user = auth_request->user;
	password = NULL;

	ret = sql_result_next_row(result);
	if (ret < 0) {
		auth_request_log_error(auth_request, "sql",
				       "Password query failed: %s",
				       sql_result_get_error(result));
	} else if (ret == 0) {
		auth_request_log_info(auth_request, "sql", "unknown user");
		passdb_result = PASSDB_RESULT_USER_UNKNOWN;
	} else {
		sql_query_save_results(result, sql_request);

		/* Note that we really want to check if the password field is
		   found. Just checking if password is set isn't enough,
		   because with proxies we might want to return NULL as
		   password. */
		if (sql_result_find_field(result, "password") < 0) {
			auth_request_log_error(auth_request, "sql",
				"Password query must return a field named "
				"'password'");
		} else if (sql_result_next_row(result) > 0) {
			auth_request_log_error(auth_request, "sql",
				"Password query returned multiple matches");
		} else {
			password = auth_request->passdb_password;
			if (password == NULL)
				auth_request->no_password = TRUE;
			passdb_result = PASSDB_RESULT_OK;
		}
	}

	scheme = password_get_scheme(&password);
	/* auth_request_set_field() sets scheme */
	i_assert(password == NULL || scheme != NULL);

	if (auth_request->credentials != -1) {
		passdb_handle_credentials(passdb_result, password, scheme,
			sql_request->callback.lookup_credentials,
			auth_request);
		auth_request_unref(&auth_request);
		return;
	}

	/* verify plain */
	if (password == NULL) {
		sql_request->callback.verify_plain(passdb_result, auth_request);
		auth_request_unref(&auth_request);
		return;
	}

	ret = password_verify(auth_request->mech_password, password,
			      scheme, user);
	if (ret < 0) {
		auth_request_log_error(auth_request, "sql",
				       "Unknown password scheme %s", scheme);
	} else if (ret == 0) {
		auth_request_log_info(auth_request, "sql", "Password mismatch");
	}

	sql_request->callback.verify_plain(ret > 0 ? PASSDB_RESULT_OK :
					   PASSDB_RESULT_PASSWORD_MISMATCH,
					   auth_request);
	auth_request_unref(&auth_request);
}

static void sql_lookup_pass(struct passdb_sql_request *sql_request)
{
	struct passdb_module *_module =
		sql_request->auth_request->passdb->passdb;
	struct sql_passdb_module *module = (struct sql_passdb_module *)_module;
	string_t *query;

	query = t_str_new(512);
	var_expand(query, module->conn->set.password_query,
		   auth_request_get_var_expand_table(sql_request->auth_request,
						     str_escape));

	auth_request_log_debug(sql_request->auth_request, "sql",
			       "query: %s", str_c(query));

	auth_request_ref(sql_request->auth_request);
	sql_query(module->conn->db, str_c(query),
		  sql_query_callback, sql_request);
}

static void sql_verify_plain(struct auth_request *request,
			     const char *password __attr_unused__,
			     verify_plain_callback_t *callback)
{
	struct passdb_sql_request *sql_request;

	sql_request = p_new(request->pool, struct passdb_sql_request, 1);
	sql_request->auth_request = request;
	sql_request->callback.verify_plain = callback;

	sql_lookup_pass(sql_request);
}

static void sql_lookup_credentials(struct auth_request *request,
				   lookup_credentials_callback_t *callback)
{
	struct passdb_sql_request *sql_request;

	sql_request = p_new(request->pool, struct passdb_sql_request, 1);
	sql_request->auth_request = request;
	sql_request->callback.lookup_credentials = callback;

        sql_lookup_pass(sql_request);
}

static struct passdb_module *
passdb_sql_preinit(struct auth_passdb *auth_passdb, const char *args)
{
	struct sql_passdb_module *module;
	struct sql_connection *conn;

	module = p_new(auth_passdb->auth->pool, struct sql_passdb_module, 1);
	module->conn = conn = db_sql_init(args);

	module->module.cache_key =
		auth_cache_parse_key(auth_passdb->auth->pool,
				     conn->set.password_query);
	module->module.default_pass_scheme = conn->set.default_pass_scheme;
	return &module->module;
}

static void passdb_sql_init(struct passdb_module *_module,
			    const char *args __attr_unused__)
{
	struct sql_passdb_module *module =
		(struct sql_passdb_module *)_module;
	enum sql_db_flags flags;

	flags = sql_get_flags(module->conn->db);
	module->module.blocking = (flags & SQL_DB_FLAG_BLOCKING) != 0;

	if (!module->module.blocking || worker)
                sql_connect(module->conn->db);
}

static void passdb_sql_deinit(struct passdb_module *_module)
{
	struct sql_passdb_module *module =
		(struct sql_passdb_module *)_module;

	db_sql_unref(&module->conn);
}

struct passdb_module_interface passdb_sql = {
	"sql",

	passdb_sql_preinit,
	passdb_sql_init,
	passdb_sql_deinit,
       
	sql_verify_plain,
	sql_lookup_credentials
};

#endif
