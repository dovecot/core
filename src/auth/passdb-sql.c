/* Copyright (C) 2004 Timo Sirainen, Alex Howansky */

#include "config.h"
#undef HAVE_CONFIG_H

#ifdef PASSDB_SQL

#include "common.h"
#include "str.h"
#include "strescape.h"
#include "var-expand.h"
#include "password-scheme.h"
#include "db-sql.h"
#include "passdb.h"
#include "passdb-cache.h"

#include <stdlib.h>
#include <string.h>

struct passdb_sql_request {
	struct auth_request *auth_request;
	enum passdb_credentials credentials;
	union {
		verify_plain_callback_t *verify_plain;
                lookup_credentials_callback_t *lookup_credentials;
	} callback;

	char password[1];
};

static struct sql_connection *passdb_sql_conn;
static char *passdb_sql_cache_key;

static void result_save_extra_fields(struct sql_result *result,
				     struct passdb_sql_request *sql_request,
				     struct auth_request *auth_request)
{
	struct auth_request_extra *extra;
	unsigned int i, fields_count;
	const char *name, *value;

	extra = auth_request_extra_begin(auth_request, sql_request->password);

	fields_count = sql_result_get_fields_count(result);
	for (i = 0; i < fields_count; i++) {
		name = sql_result_get_field_name(result, i);
		value = sql_result_get_field_value(result, i);

		if (value != NULL)
			auth_request_extra_next(extra, name, value);
	}

	auth_request_extra_finish(extra, passdb_sql_cache_key);
}

static void sql_query_callback(struct sql_result *result, void *context)
{
	struct passdb_sql_request *sql_request = context;
	struct auth_request *auth_request = sql_request->auth_request;
	enum passdb_result passdb_result;
	const char *user, *password, *scheme;
	int ret, idx;

	passdb_result = PASSDB_RESULT_USER_UNKNOWN;
	user = auth_request->user;
	password = NULL;

	ret = sql_result_next_row(result);
	if (ret < 0) {
		i_error("sql(%s): Password query failed: %s",
			get_log_prefix(auth_request),
			sql_result_get_error(result));
		passdb_result = PASSDB_RESULT_INTERNAL_FAILURE;
	} else if (ret == 0) {
		if (verbose) {
			i_info("sql(%s): Unknown user",
			       get_log_prefix(auth_request));
		}
		if (passdb_cache != NULL) {
			auth_cache_insert(passdb_cache, auth_request,
					  passdb_sql_cache_key, "");
		}
	} else if ((idx = sql_result_find_field(result, "password")) < 0) {
		i_error("sql(%s): Password query must return a field named "
			"\"password\"", get_log_prefix(auth_request));
	} else {
		password = t_strdup(sql_result_get_field_value(result, idx));
                result_save_extra_fields(result, sql_request, auth_request);
	}

	if (ret > 0) {
		/* make sure there was only one row returned */
		if (sql_result_next_row(result) > 0) {
			i_error("sql(%s): Password query returned multiple "
				"matches", get_log_prefix(auth_request));
			password = NULL;
		}
	}

	scheme = password_get_scheme(&password);
	if (scheme == NULL) {
		scheme = passdb_sql_conn->set.default_pass_scheme;
		i_assert(scheme != NULL);
	}

	if (sql_request->credentials != -1) {
		passdb_handle_credentials(passdb_result,
			sql_request->credentials, password, scheme,
			sql_request->callback.lookup_credentials,
			auth_request);
		i_free(sql_request);
		return;
	}

	/* verify plain */
	if (password == NULL) {
		sql_request->callback.verify_plain(passdb_result, auth_request);
		i_free(sql_request);
		return;
	}

	ret = password_verify(sql_request->password, password, scheme, user);
	if (ret < 0) {
		i_error("sql(%s): Unknown password scheme %s",
			get_log_prefix(auth_request), scheme);
	} else if (ret == 0) {
		if (verbose) {
			i_info("sql(%s): Password mismatch",
			       get_log_prefix(auth_request));
		}
	}

	sql_request->callback.verify_plain(ret > 0 ? PASSDB_RESULT_OK :
					   PASSDB_RESULT_PASSWORD_MISMATCH,
					   auth_request);
	i_free(sql_request);
}

static void sql_lookup_pass(struct passdb_sql_request *sql_request)
{
	string_t *query;

	query = t_str_new(512);
	var_expand(query, passdb_sql_conn->set.password_query,
		   auth_request_get_var_expand_table(sql_request->auth_request,
						     str_escape));

	if (verbose_debug) {
		i_info("sql(%s): query: %s",
		       get_log_prefix(sql_request->auth_request), str_c(query));
	}

	sql_query(passdb_sql_conn->db, str_c(query),
		  sql_query_callback, sql_request);
}

static void sql_verify_plain(struct auth_request *request, const char *password,
			     verify_plain_callback_t *callback)
{
	struct passdb_sql_request *sql_request;
	enum passdb_result result;

	if (passdb_cache_verify_plain(request, passdb_sql_cache_key, password,
				      passdb_sql_conn->set.default_pass_scheme,
				      &result)) {
		callback(result, request);
		return;
	}

	sql_request = i_malloc(sizeof(struct passdb_sql_request) +
			       strlen(password));
	sql_request->auth_request = request;
	sql_request->credentials = -1;
	sql_request->callback.verify_plain = callback;
	strcpy(sql_request->password, password);

	sql_lookup_pass(sql_request);
}

static void sql_lookup_credentials(struct auth_request *request,
				   enum passdb_credentials credentials,
				   lookup_credentials_callback_t *callback)
{
	struct passdb_sql_request *sql_request;
	const char *result, *scheme;

	if (passdb_cache_lookup_credentials(request, passdb_sql_cache_key,
					    &result, &scheme)) {
		if (scheme == NULL)
			scheme = passdb_sql_conn->set.default_pass_scheme;
		passdb_handle_credentials(result != NULL ? PASSDB_RESULT_OK :
					  PASSDB_RESULT_USER_UNKNOWN,
					  credentials, result, scheme,
					  callback, request);
		return;
	}

	sql_request = i_new(struct passdb_sql_request, 1);
	sql_request->auth_request = request;
	sql_request->credentials = credentials;
	sql_request->callback.lookup_credentials = callback;

        sql_lookup_pass(sql_request);
}

static void passdb_sql_preinit(const char *args)
{
	passdb_sql_conn = db_sql_init(args);
	passdb_sql_cache_key =
		auth_cache_parse_key(passdb_sql_conn->set.password_query);
}

static void passdb_sql_init(const char *args __attr_unused__)
{
	db_sql_connect(passdb_sql_conn);
}

static void passdb_sql_deinit(void)
{
	db_sql_unref(passdb_sql_conn);
	i_free(passdb_sql_cache_key);
}

struct passdb_module passdb_sql = {
	"sql",

	passdb_sql_preinit,
	passdb_sql_init,
	passdb_sql_deinit,

	sql_verify_plain,
	sql_lookup_credentials
};

#endif
