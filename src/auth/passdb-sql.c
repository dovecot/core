/* Copyright (c) 2004-2018 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "passdb.h"

#ifdef PASSDB_SQL

#include "safe-memset.h"
#include "password-scheme.h"
#include "auth-cache.h"
#include "db-sql.h"

#include <string.h>

struct sql_passdb_module {
	struct passdb_module module;

	struct db_sql_connection *conn;
};

struct passdb_sql_request {
	struct auth_request *auth_request;
	union {
		verify_plain_callback_t *verify_plain;
                lookup_credentials_callback_t *lookup_credentials;
		set_credentials_callback_t *set_credentials;
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

		if (*name == '\0')
			;
		else if (value == NULL)
			auth_request_set_null_field(auth_request, name);
		else {
			auth_request_set_field(auth_request, name, value,
				module->conn->set.default_pass_scheme);
		}
	}
}

static void sql_query_callback(struct sql_result *result,
			       struct passdb_sql_request *sql_request)
{
	struct auth_request *auth_request = sql_request->auth_request;
	struct passdb_module *_module = auth_request->passdb->passdb;
	struct sql_passdb_module *module = (struct sql_passdb_module *)_module;
	enum passdb_result passdb_result;
	const char *password, *scheme;
	int ret;

	passdb_result = PASSDB_RESULT_INTERNAL_FAILURE;
	password = NULL;

	ret = sql_result_next_row(result);
	if (ret >= 0)
		db_sql_success(module->conn);
	if (ret < 0) {
		if (!module->conn->default_password_query) {
			auth_request_log_error(auth_request, AUTH_SUBSYS_DB,
					       "Password query failed: %s",
					       sql_result_get_error(result));
		} else {
			auth_request_log_error(auth_request, AUTH_SUBSYS_DB,
				"Password query failed: %s "
				"(using built-in default password_query: %s)",
				sql_result_get_error(result),
				module->conn->set.password_query);
		}
	} else if (ret == 0) {
		auth_request_log_unknown_user(auth_request, AUTH_SUBSYS_DB);
		passdb_result = PASSDB_RESULT_USER_UNKNOWN;
	} else {
		sql_query_save_results(result, sql_request);

		/* Note that we really want to check if the password field is
		   found. Just checking if password is set isn't enough,
		   because with proxies we might want to return NULL as
		   password. */
		if (sql_result_find_field(result, "password") < 0 &&
		    sql_result_find_field(result, "password_noscheme") < 0) {
			auth_request_log_error(auth_request, AUTH_SUBSYS_DB,
				"Password query must return a field named "
				"'password'");
		} else if (sql_result_next_row(result) > 0) {
			auth_request_log_error(auth_request, AUTH_SUBSYS_DB,
				"Password query returned multiple matches");
		} else if (auth_request->passdb_password == NULL &&
			   !auth_fields_exists(auth_request->extra_fields, "nopassword")) {
			auth_request_log_info(auth_request, AUTH_SUBSYS_DB,
				"Empty password returned without nopassword");
			passdb_result = PASSDB_RESULT_PASSWORD_MISMATCH;
		} else {
			/* passdb_password may change on the way,
			   so we'll need to strdup. */
			password = t_strdup(auth_request->passdb_password);
			passdb_result = PASSDB_RESULT_OK;
		}
	}

	scheme = password_get_scheme(&password);
	/* auth_request_set_field() sets scheme */
	i_assert(password == NULL || scheme != NULL);

	if (auth_request->credentials_scheme != NULL) {
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

	ret = auth_request_password_verify(auth_request,
					   auth_request->mech_password,
					   password, scheme, AUTH_SUBSYS_DB);

	sql_request->callback.verify_plain(ret > 0 ? PASSDB_RESULT_OK :
					   PASSDB_RESULT_PASSWORD_MISMATCH,
					   auth_request);
	auth_request_unref(&auth_request);
}

static const char *
passdb_sql_escape(const char *str, const struct auth_request *auth_request)
{
	struct passdb_module *_module = auth_request->passdb->passdb;
	struct sql_passdb_module *module = (struct sql_passdb_module *)_module;

	return sql_escape_string(module->conn->db, str);
}

static void sql_lookup_pass(struct passdb_sql_request *sql_request)
{
	struct passdb_module *_module =
		sql_request->auth_request->passdb->passdb;
	struct sql_passdb_module *module = (struct sql_passdb_module *)_module;
	const char *query, *error;

	if (t_auth_request_var_expand(module->conn->set.password_query,
				      sql_request->auth_request,
				      passdb_sql_escape, &query, &error) <= 0) {
		auth_request_log_debug(sql_request->auth_request, AUTH_SUBSYS_DB,
			"Failed to expand password_query=%s: %s",
			module->conn->set.password_query, error);
		sql_request->callback.verify_plain(PASSDB_RESULT_INTERNAL_FAILURE,
						   sql_request->auth_request);
		return;
	}

	auth_request_log_debug(sql_request->auth_request, AUTH_SUBSYS_DB,
			       "query: %s", query);

	auth_request_ref(sql_request->auth_request);
	sql_query(module->conn->db, query,
		  sql_query_callback, sql_request);
}

static void sql_verify_plain(struct auth_request *request,
			     const char *password ATTR_UNUSED,
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

static void sql_set_credentials_callback(const struct sql_commit_result *sql_result,
					 struct passdb_sql_request *sql_request)
{
	struct passdb_module *_module =
		sql_request->auth_request->passdb->passdb;
	struct sql_passdb_module *module = (struct sql_passdb_module *)_module;

	if (sql_result->error != NULL) {
		if (!module->conn->default_update_query) {
			auth_request_log_error(sql_request->auth_request,
				AUTH_SUBSYS_DB,
				"Set credentials query failed: %s", sql_result->error);
		} else {
			auth_request_log_error(sql_request->auth_request,
				AUTH_SUBSYS_DB,
				"Set credentials query failed: %s"
				"(using built-in default update_query: %s)",
				sql_result->error, module->conn->set.update_query);
		}
	}

	sql_request->callback.
		set_credentials(sql_result->error == NULL, sql_request->auth_request);
	i_free(sql_request);
}

static void sql_set_credentials(struct auth_request *request,
				const char *new_credentials,
				set_credentials_callback_t *callback)
{
	struct sql_passdb_module *module =
		(struct sql_passdb_module *) request->passdb->passdb;
	struct sql_transaction_context *transaction;
	struct passdb_sql_request *sql_request;
	const char *query, *error;

	request->mech_password = p_strdup(request->pool, new_credentials);

	if (t_auth_request_var_expand(module->conn->set.update_query,
				      request, passdb_sql_escape,
				      &query, &error) <= 0) {
		auth_request_log_error(request, AUTH_SUBSYS_DB,
			"Failed to expand update_query=%s: %s",
			module->conn->set.update_query, error);
		callback(FALSE, request);
		return;
	}

	sql_request = i_new(struct passdb_sql_request, 1);
	sql_request->auth_request = request;
	sql_request->callback.set_credentials = callback;

	transaction = sql_transaction_begin(module->conn->db);
	sql_update(transaction, query);
	sql_transaction_commit(&transaction,
			       sql_set_credentials_callback, sql_request);
}

static struct passdb_module *
passdb_sql_preinit(pool_t pool, const char *args)
{
	struct sql_passdb_module *module;
	struct db_sql_connection *conn;

	module = p_new(pool, struct sql_passdb_module, 1);
	module->conn = conn = db_sql_init(args, FALSE);

	module->module.default_cache_key =
		auth_cache_parse_key(pool, conn->set.password_query);
	module->module.default_pass_scheme = conn->set.default_pass_scheme;
	return &module->module;
}

static void passdb_sql_init(struct passdb_module *_module)
{
	struct sql_passdb_module *module =
		(struct sql_passdb_module *)_module;
	enum sql_db_flags flags;

	flags = sql_get_flags(module->conn->db);
	module->module.blocking = (flags & SQL_DB_FLAG_BLOCKING) != 0;

	if (!module->module.blocking || worker)
		db_sql_connect(module->conn);
	db_sql_check_userdb_warning(module->conn);
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
	sql_lookup_credentials,
	sql_set_credentials
};
#else
struct passdb_module_interface passdb_sql = {
	.name = "sql"
};
#endif
