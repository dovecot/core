/* Copyright (C) 2003 Alex Howansky, Timo Sirainen */

#include "config.h"
#undef HAVE_CONFIG_H

#ifdef PASSDB_MYSQL

#include "common.h"
#include "str.h"
#include "strescape.h"
#include "var-expand.h"
#include "password-scheme.h"
#include "db-mysql.h"
#include "passdb.h"

#include <stdlib.h>
#include <string.h>

struct passdb_mysql_connection {
	struct mysql_connection *conn;
};

struct passdb_mysql_request {
	struct mysql_request request;

	enum passdb_credentials credentials;
	union {
		verify_plain_callback_t *verify_plain;
                lookup_credentials_callback_t *lookup_credentials;
	} callback;

	char password[1];
};

static struct passdb_mysql_connection *passdb_mysql_conn;

static void mysql_handle_request(struct mysql_connection *conn,
				 struct mysql_request *request, MYSQL_RES *res)
{
	struct passdb_mysql_request *mysql_request =
		(struct passdb_mysql_request *) request;
	struct auth_request *auth_request = request->context;
	const char *user, *password, *scheme;
	int ret = 0;

	user = auth_request->user;
	password = NULL;

	if (res != NULL) {
		if (mysql_num_rows(res) == 0) {
			if (verbose) {
				i_info("mysql(%s): Unknown user",
				       get_log_prefix(auth_request));
			}
		} else if (mysql_num_rows(res) > 1) {
			i_error("mysql(%s): Multiple matches for user",
				get_log_prefix(auth_request));
		} else if (mysql_num_fields(res) != 1) {
			i_error("mysql(%s): Password query returned "
				"more than one field",
				get_log_prefix(auth_request));
		} else {
			MYSQL_ROW row;

			row = mysql_fetch_row(res);
			if (row)
				password = t_strdup(row[0]);
		}
	}

	scheme = password_get_scheme(&password);
	if (scheme == NULL) {
		scheme = conn->set.default_pass_scheme;
		i_assert(scheme != NULL);
	}

	if (mysql_request->credentials != -1) {
		passdb_handle_credentials(mysql_request->credentials,
			user, password, scheme,
			mysql_request->callback.lookup_credentials,
			auth_request);
		return;
	}

	/* verify plain */
	if (password == NULL) {
		mysql_request->callback.verify_plain(PASSDB_RESULT_USER_UNKNOWN,
						     auth_request);
		return;
	}

	ret = password_verify(mysql_request->password, password,
			      scheme, user);
	if (ret < 0) {
		i_error("mysql(%s): Unknown password scheme %s",
			get_log_prefix(auth_request), scheme);
	} else if (ret == 0) {
		if (verbose) {
			i_info("mysql(%s): Password mismatch",
			       get_log_prefix(auth_request));
		}
	}

	mysql_request->callback.verify_plain(ret > 0 ? PASSDB_RESULT_OK :
					     PASSDB_RESULT_PASSWORD_MISMATCH,
					     auth_request);
}

static void mysql_lookup_pass(struct auth_request *auth_request,
			      struct mysql_request *mysql_request)
{
	struct mysql_connection *conn = passdb_mysql_conn->conn;
	const char *query;
	string_t *str;

	str = t_str_new(512);
	var_expand(str, conn->set.password_query,
		   auth_request_get_var_expand_table(auth_request,
						     str_escape));
	query = str_c(str);

	mysql_request->callback = mysql_handle_request;
	mysql_request->context = auth_request;

	db_mysql_query(conn, query, mysql_request);
}

static void
mysql_verify_plain(struct auth_request *request, const char *password,
		   verify_plain_callback_t *callback)
{
	struct passdb_mysql_request *mysql_request;

	mysql_request = i_malloc(sizeof(struct passdb_mysql_request) +
				 strlen(password));
	mysql_request->credentials = -1;
	mysql_request->callback.verify_plain = callback;
	strcpy(mysql_request->password, password);

	mysql_lookup_pass(request, &mysql_request->request);
}

static void mysql_lookup_credentials(struct auth_request *request,
				     enum passdb_credentials credentials,
				     lookup_credentials_callback_t *callback)
{
	struct passdb_mysql_request *mysql_request;

	mysql_request = i_new(struct passdb_mysql_request, 1);
	mysql_request->credentials = credentials;
	mysql_request->callback.lookup_credentials = callback;

        mysql_lookup_pass(request, &mysql_request->request);
}

static void passdb_mysql_preinit(const char *args)
{
	struct mysql_connection *conn;

	passdb_mysql_conn = i_new(struct passdb_mysql_connection, 1);
	passdb_mysql_conn->conn = conn = db_mysql_init(args);
}

static void passdb_mysql_init(const char *args __attr_unused__)
{
	(void)db_mysql_connect(passdb_mysql_conn->conn);
}

static void passdb_mysql_deinit(void)
{
	db_mysql_unref(passdb_mysql_conn->conn);
	i_free(passdb_mysql_conn);
}

struct passdb_module passdb_mysql = {
	passdb_mysql_preinit,
	passdb_mysql_init,
	passdb_mysql_deinit,

	mysql_verify_plain,
	mysql_lookup_credentials
};

#endif
