/* Copyright (C) 2003 Timo Sirainen */

#include "config.h"
#undef HAVE_CONFIG_H

#ifdef PASSDB_LDAP

#include "common.h"
#include "hash.h"
#include "str.h"
#include "var-expand.h"
#include "password-scheme.h"
#include "db-ldap.h"
#include "passdb.h"
#include "passdb-cache.h"

#include <ldap.h>
#include <stdlib.h>

static const char *default_attr_map[] = {
	"user", "password", NULL
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

static struct ldap_connection *passdb_ldap_conn;
static char *passdb_ldap_cache_key;

static const char *
ldap_query_save_result(struct ldap_connection *conn, LDAPMessage *entry,
                       struct passdb_ldap_request *ldap_request,
		       struct auth_request *auth_request)
{
	struct auth_request_extra *extra;
	BerElement *ber;
	const char *name, *password;
	char *attr, **vals;
	unsigned int i;

	extra = auth_request_extra_begin(auth_request);

	password = NULL;
	attr = ldap_first_attribute(conn->ld, entry, &ber);
	while (attr != NULL) {
		name = hash_lookup(passdb_ldap_conn->attr_map, attr);
		vals = ldap_get_values(conn->ld, entry, attr);

		if (name != NULL && vals != NULL && vals[0] != NULL) {
			if (strcmp(name, "password") == 0 && vals[1] == NULL)
				password = t_strdup(vals[0]);
			for (i = 0; vals[i] != NULL; i++)
				auth_request_extra_next(extra, name, vals[i]);
		}

		ldap_value_free(vals);
		ldap_memfree(attr);

		attr = ldap_next_attribute(conn->ld, entry, ber);
	}

	auth_request_extra_finish(extra, ldap_request->password, NULL);
	return password;
}

static void handle_request(struct ldap_connection *conn,
			   struct ldap_request *request, LDAPMessage *res)
{
	struct passdb_ldap_request *ldap_request =
		(struct passdb_ldap_request *) request;
        struct auth_request *auth_request = request->context;
	enum passdb_result result;
	LDAPMessage *entry;
	const char *password, *scheme;
	int ret;

	result = PASSDB_RESULT_USER_UNKNOWN;
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
		password = ldap_query_save_result(conn, entry, ldap_request,
						  auth_request);

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

	ret = password_verify(ldap_request->password, password, scheme,
			      auth_request->user);
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
	struct ldap_connection *conn = passdb_ldap_conn;
        const struct var_expand_table *vars;
	const char **attr_names = (const char **)conn->attr_names;
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
	struct passdb_ldap_request *ldap_request;
	enum passdb_result result;

	if (passdb_cache_verify_plain(request, passdb_ldap_cache_key, password,
				      passdb_ldap_conn->set.default_pass_scheme,
				      &result)) {
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
		if (scheme == NULL)
			scheme = passdb_ldap_conn->set.default_pass_scheme;
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
	passdb_ldap_conn = db_ldap_init(args);

	db_ldap_set_attrs(passdb_ldap_conn, passdb_ldap_conn->set.pass_attrs,
			  default_attr_map);
	passdb_ldap_cache_key =
		auth_cache_parse_key(passdb_ldap_conn->set.pass_filter);
}

static void passdb_ldap_init(const char *args __attr_unused__)
{
	(void)db_ldap_connect(passdb_ldap_conn);
}

static void passdb_ldap_deinit(void)
{
	db_ldap_unref(passdb_ldap_conn);
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
