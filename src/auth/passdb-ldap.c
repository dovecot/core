/* Copyright (C) 2003 Timo Sirainen */

#include "config.h"
#undef HAVE_CONFIG_H

#ifdef PASSDB_LDAP

#include "common.h"
#include "str.h"
#include "var-expand.h"
#include "password-scheme.h"
#include "db-ldap.h"
#include "passdb.h"
#include "passdb-cache.h"

#include <ldap.h>
#include <stdlib.h>

enum ldap_user_attr {
	ATTR_VIRTUAL_USER = 0,
	ATTR_PASSWORD,

	ATTR_COUNT
};

struct passdb_ldap_connection {
	struct ldap_connection *conn;

        unsigned int *attrs;
	char **attr_names;
};

struct passdb_ldap_request {
	struct ldap_request request;

	enum passdb_credentials credentials;
	union {
		verify_plain_callback_t *verify_plain;
                lookup_credentials_callback_t *lookup_credentials;
	} callback;

	char password[1]; /* variable width */
};

static struct passdb_ldap_connection *passdb_ldap_conn;
static char *passdb_ldap_cache_key;

static void handle_request(struct ldap_connection *conn,
			   struct ldap_request *request, LDAPMessage *res)
{
	struct passdb_ldap_request *ldap_request =
		(struct passdb_ldap_request *) request;
        struct auth_request *auth_request = request->context;
	enum passdb_result result;
	LDAPMessage *entry;
	BerElement *ber;
	char *attr, **vals;
	const char *user, *password, *scheme;
	int ret;

	result = PASSDB_RESULT_USER_UNKNOWN;
	user = auth_request->user;
	password = NULL;

	if (res != NULL) {
		ret = ldap_result2error(conn->ld, res, 0);
		if (ret != LDAP_SUCCESS) {
			auth_request_log_error(auth_request, "ldap",
					       "ldap_search() failed: %s",
					       ldap_err2string(ret));

                        result = PASSDB_RESULT_INTERNAL_FAILURE;
			res = NULL;
		}
	}

	entry = res == NULL ? NULL : ldap_first_entry(conn->ld, res);
	if (entry == NULL) {
		if (res != NULL) {
			auth_request_log_info(auth_request, "ldap",
					      "unknown user");
		}
	} else {
		attr = ldap_first_attribute(conn->ld, entry, &ber);
		while (attr != NULL) {
			vals = ldap_get_values(conn->ld, entry, attr);
			if (vals != NULL && vals[0] != NULL &&
			    vals[1] == NULL) {
				if (strcasecmp(attr, passdb_ldap_conn->
					       attr_names[ATTR_PASSWORD]) == 0)
					password = t_strdup(vals[0]);
			}
			ldap_value_free(vals);
			ldap_memfree(attr);

			attr = ldap_next_attribute(conn->ld, entry, ber);
		}

		if (password == NULL) {
			auth_request_log_error(auth_request, "ldap",
					       "No password in reply");
		} else if (ldap_next_entry(conn->ld, entry) != NULL) {
			auth_request_log_error(auth_request, "ldap",
					       "Multiple password replies");
			password = NULL;
		}
	}

	/* LDAP result is freed now. we can check if auth_request is
	   even needed anymore */
	if (!auth_request_unref(auth_request))
		return;

	scheme = password_get_scheme(&password);
	if (scheme == NULL) {
		scheme = conn->set.default_pass_scheme;
		i_assert(scheme != NULL);
	}

	if (ldap_request->credentials != -1) {
		passdb_handle_credentials(result, ldap_request->credentials,
			password, scheme,
			ldap_request->callback.lookup_credentials,
			auth_request);
		return;
	}

	/* verify plain */
	if (password == NULL) {
		ldap_request->callback.verify_plain(result, auth_request);
		return;
	}

	ret = password_verify(ldap_request->password, password, scheme, user);
	if (ret < 0) {
		auth_request_log_error(auth_request, "ldap",
			"Unknown password scheme %s", scheme);
	} else if (ret == 0) {
		auth_request_log_info(auth_request, "ldap",
				      "password mismatch");
	}

	ldap_request->callback.verify_plain(ret > 0 ? PASSDB_RESULT_OK :
					    PASSDB_RESULT_PASSWORD_MISMATCH,
					    auth_request);
}

static void ldap_lookup_pass(struct auth_request *auth_request,
			     struct ldap_request *ldap_request)
{
	struct ldap_connection *conn = passdb_ldap_conn->conn;
        const struct var_expand_table *vars;
	const char **attr_names = (const char **)passdb_ldap_conn->attr_names;
	const char *filter, *base;
	string_t *str;

	vars = auth_request_get_var_expand_table(auth_request, ldap_escape);

	str = t_str_new(512);
	var_expand(str, conn->set.base, vars);
	base = t_strdup(str_c(str));

	str_truncate(str, 0);
	var_expand(str, conn->set.pass_filter, vars);
	filter = str_c(str);

	auth_request_ref(auth_request);
	ldap_request->callback = handle_request;
	ldap_request->context = auth_request;

	auth_request_log_debug(auth_request, "ldap",
			       "base=%s scope=%s filter=%s fields=%s",
			       base, conn->set.scope, filter,
			       t_strarray_join(attr_names, ","));

	db_ldap_search(conn, base, conn->set.ldap_scope,
		       filter, passdb_ldap_conn->attr_names,
		       ldap_request);
}

static void
ldap_verify_plain(struct auth_request *request, const char *password,
		  verify_plain_callback_t *callback)
{
	struct ldap_connection *conn = passdb_ldap_conn->conn;
	struct passdb_ldap_request *ldap_request;
	enum passdb_result result;

	if (passdb_cache_verify_plain(request, passdb_ldap_cache_key, password,
				      conn->set.default_pass_scheme, &result)) {
		callback(result, request);
		return;
	}

	ldap_request = i_malloc(sizeof(struct passdb_ldap_request) +
				strlen(password));
	ldap_request->credentials = -1;
	ldap_request->callback.verify_plain = callback;
	strcpy(ldap_request->password, password);

        ldap_lookup_pass(request, &ldap_request->request);
}

static void ldap_lookup_credentials(struct auth_request *request,
				    enum passdb_credentials credentials,
				    lookup_credentials_callback_t *callback)
{
	struct passdb_ldap_request *ldap_request;
	const char *result, *scheme;

	if (passdb_cache_lookup_credentials(request, passdb_ldap_cache_key,
					    &result, &scheme)) {
		if (scheme == NULL) {
			scheme = passdb_ldap_conn->conn->set.
				default_pass_scheme;
		}
		passdb_handle_credentials(result != NULL ? PASSDB_RESULT_OK :
					  PASSDB_RESULT_USER_UNKNOWN,
					  credentials, result, scheme,
					  callback, request);
		return;
	}

	ldap_request = i_new(struct passdb_ldap_request, 1);
	ldap_request->credentials = credentials;
	ldap_request->callback.lookup_credentials = callback;

        ldap_lookup_pass(request, &ldap_request->request);
}

static void passdb_ldap_preinit(const char *args)
{
	struct ldap_connection *conn;

	passdb_ldap_conn = i_new(struct passdb_ldap_connection, 1);
	passdb_ldap_conn->conn = conn = db_ldap_init(args);

	db_ldap_set_attrs(conn, conn->set.pass_attrs, &passdb_ldap_conn->attrs,
			  &passdb_ldap_conn->attr_names);
	passdb_ldap_cache_key = auth_cache_parse_key(conn->set.pass_filter);
}

static void passdb_ldap_init(const char *args __attr_unused__)
{
	(void)db_ldap_connect(passdb_ldap_conn->conn);
}

static void passdb_ldap_deinit(void)
{
	db_ldap_unref(passdb_ldap_conn->conn);
	i_free(passdb_ldap_cache_key);
	i_free(passdb_ldap_conn);
}

struct passdb_module passdb_ldap = {
	"ldap",

	passdb_ldap_preinit,
	passdb_ldap_init,
	passdb_ldap_deinit,

	ldap_verify_plain,
	ldap_lookup_credentials
};

#endif
