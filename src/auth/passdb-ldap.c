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

#include <ldap.h>
#include <stdlib.h>

/* using posixAccount */
#define DEFAULT_ATTRIBUTES "uid,userPassword"

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

static void handle_request(struct ldap_connection *conn,
			   struct ldap_request *request, LDAPMessage *res)
{
	struct passdb_ldap_request *ldap_request =
		(struct passdb_ldap_request *) request;
        struct auth_request *auth_request = request->context;
	LDAPMessage *entry;
	BerElement *ber;
	char *attr, **vals;
	const char *user, *password, *scheme;
	int ret;

	user = auth_request->user;
	password = NULL;

	if (res != NULL) {
		ret = ldap_result2error(conn->ld, res, 0);
		if (ret != LDAP_SUCCESS) {
			i_error("ldap(%s): ldap_search() failed: %s",
				user, ldap_err2string(ret));
			res = NULL;
		}
	}

	entry = res == NULL ? NULL : ldap_first_entry(conn->ld, res);
	if (entry == NULL) {
		if (res != NULL)
			i_error("ldap(%s): unknown user", user);
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

		if (password == NULL)
			i_error("ldap(%s): No password in reply", user);
		else if (ldap_next_entry(conn->ld, entry) != NULL) {
			i_error("ldap(%s): Multiple password replies", user);
			password = NULL;
		}
	}

	scheme = password_get_scheme(&password);
	if (scheme == NULL) {
		scheme = conn->set.default_pass_scheme;
		i_assert(scheme != NULL);
	}

	if (ldap_request->credentials != -1) {
		passdb_handle_credentials(ldap_request->credentials,
			user, password, scheme,
			ldap_request->callback.lookup_credentials,
			auth_request);
		return;
	}

	/* verify plain */
	if (password == NULL) {
		ldap_request->callback.verify_plain(PASSDB_RESULT_USER_UNKNOWN,
						    auth_request);
		return;
	}

	ret = password_verify(ldap_request->password, password, scheme, user);
	if (ret < 0)
		i_error("ldap(%s): Unknown password scheme %s", user, scheme);
	else if (ret == 0) {
		if (verbose)
			i_info("ldap(%s): password mismatch", user);
	}

	ldap_request->callback.verify_plain(ret > 0 ? PASSDB_RESULT_OK :
					    PASSDB_RESULT_PASSWORD_MISMATCH,
					    auth_request);
}

static void ldap_lookup_pass(struct auth_request *auth_request,
			     struct ldap_request *ldap_request)
{
	struct ldap_connection *conn = passdb_ldap_conn->conn;
	const char *user, *filter;
	string_t *str;

	user = ldap_escape(auth_request->user);
	if (conn->set.pass_filter == NULL) {
		filter = t_strdup_printf("(&(objectClass=posixAccount)(%s=%s))",
			passdb_ldap_conn->attr_names[ATTR_VIRTUAL_USER], user);
	} else {
		str = t_str_new(512);
		var_expand(str, conn->set.pass_filter, user, NULL);
		filter = str_c(str);
	}

	ldap_request->callback = handle_request;
	ldap_request->context = auth_request;

	db_ldap_search(conn, conn->set.base, conn->set.ldap_scope,
		       filter, passdb_ldap_conn->attr_names,
		       ldap_request);
}

static void
ldap_verify_plain(struct auth_request *request, const char *password,
		  verify_plain_callback_t *callback)
{
	struct passdb_ldap_request *ldap_request;

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

	ldap_request = i_new(struct passdb_ldap_request, 1);
	ldap_request->credentials = credentials;
	ldap_request->callback.lookup_credentials = callback;

        ldap_lookup_pass(request, &ldap_request->request);
}

static void passdb_ldap_init(const char *args)
{
	struct ldap_connection *conn;

	passdb_ldap_conn = i_new(struct passdb_ldap_connection, 1);
	passdb_ldap_conn->conn = conn = db_ldap_init(args);

	db_ldap_set_attrs(conn, conn->set.pass_attrs ?
			  conn->set.pass_attrs : DEFAULT_ATTRIBUTES,
			  &passdb_ldap_conn->attrs,
			  &passdb_ldap_conn->attr_names);
}

static void passdb_ldap_deinit(void)
{
	db_ldap_unref(passdb_ldap_conn->conn);
	i_free(passdb_ldap_conn);
}

struct passdb_module passdb_ldap = {
	passdb_ldap_init,
	passdb_ldap_deinit,

	ldap_verify_plain,
	ldap_lookup_credentials
};

#endif
