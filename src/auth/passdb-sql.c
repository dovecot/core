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

static void result_save_extra_fields(struct sql_result *result,
                                     struct passdb_sql_request *sql_request,
				     struct auth_request *auth_request)
{
	unsigned int i, fields_count;
	const char *name, *value;
	string_t *str;

	fields_count = sql_result_get_fields_count(result);
	if (fields_count == 1)
		return;

	str = NULL;
	for (i = 0; i < fields_count; i++) {
		name = sql_result_get_field_name(result, i);
		value = sql_result_get_field_value(result, i);

		if (strcmp(name, "password") == 0)
			continue;

		if (strcmp(name, "nodelay") == 0) {
			/* don't delay replying to client of the failure */
			auth_request->no_failure_delay = *value == 'Y';
			continue;
		}

		if (str == NULL)
			str = str_new(auth_request->pool, 64);

		if (strcmp(name, "nologin") == 0) {
			if (*value == 'Y') {
				/* user can't actually login - don't keep this
				   reply for master */
				auth_request->no_login = TRUE;
				if (str_len(str) > 0)
					str_append_c(str, '\t');
				str_append(str, name);
			}
		} else if (strcmp(name, "proxy") == 0) {
			if (*value == 'Y') {
				/* we're proxying authentication for this
				   user. send password back if using plaintext
				   authentication. */
				auth_request->proxy = TRUE;
				if (str_len(str) > 0)
					str_append_c(str, '\t');
				str_append(str, name);

				if (*sql_request->password != '\0') {
					str_printfa(str, "\tpass=%s",
						    sql_request->password);
				}
			}
		} else {
			if (str_len(str) > 0)
				str_append_c(str, '\t');
			str_printfa(str, "%s=%s", name, value);
		}
	}

	if (str != NULL)
		auth_request->extra_fields = str_c(str);
}

static void sql_query_callback(struct sql_result *result, void *context)
{
	struct passdb_sql_request *sql_request = context;
	struct auth_request *auth_request = sql_request->auth_request;
	const char *user, *password, *scheme;
	int ret, idx;

	user = auth_request->user;
	password = NULL;

	ret = sql_result_next_row(result);
	if (ret < 0) {
		i_error("sql(%s): Password query failed: %s",
			get_log_prefix(auth_request),
			sql_result_get_error(result));
	} else if (ret == 0) {
		if (verbose) {
			i_info("sql(%s): Unknown user",
			       get_log_prefix(auth_request));
		}
	} else if ((idx = sql_result_find_field(result, "password")) < 0) {
		i_error("sql(%s): Password query didn't return password",
			get_log_prefix(auth_request));
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
		passdb_handle_credentials(sql_request->credentials,
			user, password, scheme,
			sql_request->callback.lookup_credentials,
			auth_request);
		return;
	}

	/* verify plain */
	if (password == NULL) {
		sql_request->callback.verify_plain(PASSDB_RESULT_USER_UNKNOWN,
						   auth_request);
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
}

static void sql_lookup_pass(struct passdb_sql_request *sql_request)
{
	string_t *query;

	query = t_str_new(512);
	var_expand(query, passdb_sql_conn->set.password_query,
		   auth_request_get_var_expand_table(sql_request->auth_request,
						     str_escape));

	sql_query(passdb_sql_conn->db, str_c(query),
		  sql_query_callback, sql_request);
}

static void sql_verify_plain(struct auth_request *request, const char *password,
			     verify_plain_callback_t *callback)
{
	struct passdb_sql_request *sql_request;

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

	sql_request = i_new(struct passdb_sql_request, 1);
	sql_request->auth_request = request;
	sql_request->credentials = credentials;
	sql_request->callback.lookup_credentials = callback;

        sql_lookup_pass(sql_request);
}

static void passdb_sql_preinit(const char *args)
{
	passdb_sql_conn = db_sql_init(args);
}

static void passdb_sql_init(const char *args __attr_unused__)
{
	db_sql_connect(passdb_sql_conn);
}

static void passdb_sql_deinit(void)
{
	db_sql_unref(passdb_sql_conn);
}

struct passdb_module passdb_sql = {
	passdb_sql_preinit,
	passdb_sql_init,
	passdb_sql_deinit,

	sql_verify_plain,
	sql_lookup_credentials
};

#endif
