/* Copyright (C) 2003 Alex Howansky, Timo Sirainen */

#include "config.h"
#undef HAVE_CONFIG_H

#ifdef PASSDB_PGSQL

#include "common.h"
#include "str.h"
#include "strescape.h"
#include "var-expand.h"
#include "password-scheme.h"
#include "db-pgsql.h"
#include "passdb.h"

#include <libpq-fe.h>
#include <stdlib.h>
#include <string.h>

struct passdb_pgsql_connection {
	struct pgsql_connection *conn;
};

struct passdb_pgsql_request {
	struct pgsql_request request;

	enum passdb_credentials credentials;
	union {
		verify_plain_callback_t *verify_plain;
                lookup_credentials_callback_t *lookup_credentials;
	} callback;

	char password[1];
};

static struct passdb_pgsql_connection *passdb_pgsql_conn;

static void pgsql_handle_request(struct pgsql_connection *conn,
				 struct pgsql_request *request, PGresult *res)
{
	struct passdb_pgsql_request *pgsql_request =
		(struct passdb_pgsql_request *) request;
	struct auth_request *auth_request = request->context;
	const char *user, *password, *scheme;
	int ret = 0;

	user = auth_request->user;
	password = NULL;

	if (res != NULL) {
		if (PQntuples(res) == 0) {
			if (verbose)
				i_info("pgsql(%s): Unknown user", user);
		} else if (PQntuples(res) > 1) {
			i_error("pgsql(%s): Multiple matches for user", user);
		} else if (PQnfields(res) != 1) {
			i_error("pgsql(%s): Password query returned "
				"more than one field", user);
		} else {
			password = t_strdup(PQgetvalue(res, 0, 0));
		}
	}

	scheme = password_get_scheme(&password);
	if (scheme == NULL) {
		scheme = conn->set.default_pass_scheme;
		i_assert(scheme != NULL);
	}

	if (pgsql_request->credentials != -1) {
		passdb_handle_credentials(pgsql_request->credentials,
			user, password, scheme,
			pgsql_request->callback.lookup_credentials,
			auth_request);
		return;
	}

	/* verify plain */
	if (password == NULL) {
		pgsql_request->callback.verify_plain(PASSDB_RESULT_USER_UNKNOWN,
						     auth_request);
		return;
	}

	ret = password_verify(pgsql_request->password, password,
			      scheme, user);
	if (ret < 0)
		i_error("pgsql(%s): Unknown password scheme %s", user, scheme);
	else if (ret == 0) {
		if (verbose)
			i_info("pgsql(%s): Password mismatch", user);
	}

	pgsql_request->callback.verify_plain(ret > 0 ? PASSDB_RESULT_OK :
					     PASSDB_RESULT_PASSWORD_MISMATCH,
					     auth_request);
}

static void pgsql_lookup_pass(struct auth_request *auth_request,
			      struct pgsql_request *pgsql_request)
{
	struct pgsql_connection *conn = passdb_pgsql_conn->conn;
	const char *query;
	string_t *str;

	str = t_str_new(512);
	var_expand(str, conn->set.password_query,
		   str_escape(auth_request->user), NULL);
	query = str_c(str);

	pgsql_request->callback = pgsql_handle_request;
	pgsql_request->context = auth_request;

	db_pgsql_query(conn, query, pgsql_request);
}

static void
pgsql_verify_plain(struct auth_request *request, const char *password,
		   verify_plain_callback_t *callback)
{
	struct passdb_pgsql_request *pgsql_request;

	pgsql_request = i_malloc(sizeof(struct passdb_pgsql_request) +
				 strlen(password));
	pgsql_request->credentials = -1;
	pgsql_request->callback.verify_plain = callback;
	strcpy(pgsql_request->password, password);

	pgsql_lookup_pass(request, &pgsql_request->request);
}

static void pgsql_lookup_credentials(struct auth_request *request,
				     enum passdb_credentials credentials,
				     lookup_credentials_callback_t *callback)
{
	struct passdb_pgsql_request *pgsql_request;

	pgsql_request = i_new(struct passdb_pgsql_request, 1);
	pgsql_request->credentials = credentials;
	pgsql_request->callback.lookup_credentials = callback;

        pgsql_lookup_pass(request, &pgsql_request->request);
}

static void passdb_pgsql_init(const char *args)
{
	struct pgsql_connection *conn;

	passdb_pgsql_conn = i_new(struct passdb_pgsql_connection, 1);
	passdb_pgsql_conn->conn = conn = db_pgsql_init(args);
}

static void passdb_pgsql_deinit(void)
{
	db_pgsql_unref(passdb_pgsql_conn->conn);
	i_free(passdb_pgsql_conn);
}

struct passdb_module passdb_pgsql = {
	passdb_pgsql_init,
	passdb_pgsql_deinit,

	pgsql_verify_plain,
	pgsql_lookup_credentials
};

#endif
