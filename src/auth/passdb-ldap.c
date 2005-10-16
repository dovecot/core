/* Copyright (C) 2003 Timo Sirainen */

#include "common.h"

#ifdef PASSDB_LDAP

#include "hash.h"
#include "str.h"
#include "var-expand.h"
#include "password-scheme.h"
#include "auth-cache.h"
#include "db-ldap.h"
#include "passdb.h"

#include <ldap.h>
#include <stdlib.h>

extern struct passdb_module passdb_ldap;

static const char *default_attr_map[] = {
	"user", "password", NULL
};

struct passdb_ldap_request {
	struct ldap_request request;

	union {
		verify_plain_callback_t *verify_plain;
                lookup_credentials_callback_t *lookup_credentials;
	} callback;
};

static struct ldap_connection *passdb_ldap_conn;
static char *passdb_ldap_cache_key;

static void
ldap_query_save_result(struct ldap_connection *conn, LDAPMessage *entry,
		       struct auth_request *auth_request)
{
	BerElement *ber;
	const char *name;
	char *attr, **vals;
	unsigned int i;
	string_t *debug = NULL;

	attr = ldap_first_attribute(conn->ld, entry, &ber);
	while (attr != NULL) {
		name = hash_lookup(passdb_ldap_conn->pass_attr_map, attr);
		vals = ldap_get_values(conn->ld, entry, attr);

		if (auth_request->auth->verbose_debug) {
			if (debug == NULL)
				debug = t_str_new(256);
			else
				str_append_c(debug, ' ');
			str_append(debug, attr);
			str_printfa(debug, "(%s)=",
				    name != NULL ? name : "?unknown?");
		}

		if (name != NULL && vals != NULL) {
			for (i = 0; vals[i] != NULL; i++) {
				if (debug != NULL) {
					if (i != 0)
						str_append_c(debug, '/');
					str_append(debug, vals[i]);
				}
				auth_request_set_field(auth_request,
						name, vals[i],
						conn->set.default_pass_scheme);
			}
		}

		ldap_value_free(vals);
		ldap_memfree(attr);

		attr = ldap_next_attribute(conn->ld, entry, ber);
	}

	if (debug != NULL) {
		auth_request_log_debug(auth_request, "ldap",
				       "%s", str_c(debug));
	}
}

static void handle_request(struct ldap_connection *conn,
			   struct ldap_request *request, LDAPMessage *res)
{
	struct passdb_ldap_request *ldap_request =
		(struct passdb_ldap_request *) request;
        struct auth_request *auth_request = request->context;
	enum passdb_result passdb_result;
	LDAPMessage *entry;
	const char *password, *scheme;
	int ret;

	passdb_result = PASSDB_RESULT_INTERNAL_FAILURE;
	password = NULL;

	if (res != NULL) {
		ret = ldap_result2error(conn->ld, res, 0);
		if (ret != LDAP_SUCCESS) {
			auth_request_log_error(auth_request, "ldap",
					       "ldap_search() failed: %s",
					       ldap_err2string(ret));
			res = NULL;
		}
	}

	entry = res == NULL ? NULL : ldap_first_entry(conn->ld, res);
	if (entry == NULL) {
		if (res != NULL) {
			auth_request_log_info(auth_request, "ldap",
					      "unknown user");
			passdb_result = PASSDB_RESULT_USER_UNKNOWN;
		}
	} else {
		ldap_query_save_result(conn, entry, auth_request);

		if (auth_request->passdb_password == NULL) {
			auth_request_log_error(auth_request, "ldap",
					       "No password in reply");
		} else if (ldap_next_entry(conn->ld, entry) != NULL) {
			auth_request_log_error(auth_request, "ldap",
					       "Multiple password replies");
		} else {
			password = auth_request->passdb_password;
			passdb_result = PASSDB_RESULT_OK;
		}
	}

	/* LDAP result is freed now. we can check if auth_request is
	   even needed anymore */
	if (!auth_request_unref(auth_request))
		return;

	scheme = password_get_scheme(&password);
	/* auth_request_set_field() sets scheme */
	i_assert(password == NULL || scheme != NULL);

	if (auth_request->credentials != -1) {
		passdb_handle_credentials(passdb_result, password, scheme,
			ldap_request->callback.lookup_credentials,
			auth_request);
		return;
	}

	/* verify plain */
	if (password == NULL) {
		ldap_request->callback.verify_plain(passdb_result,
						    auth_request);
		return;
	}

	ret = password_verify(auth_request->mech_password, password, scheme,
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
	const char **attr_names = (const char **)conn->pass_attr_names;
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
		       filter, passdb_ldap_conn->pass_attr_names,
		       ldap_request);
}

static void
ldap_verify_plain(struct auth_request *request,
		  const char *password __attr_unused__,
		  verify_plain_callback_t *callback)
{
	struct passdb_ldap_request *ldap_request;

	ldap_request = p_new(request->pool, struct passdb_ldap_request, 1);
	ldap_request->callback.verify_plain = callback;

        ldap_lookup_pass(request, &ldap_request->request);
}

static void ldap_lookup_credentials(struct auth_request *request,
				    lookup_credentials_callback_t *callback)
{
	struct passdb_ldap_request *ldap_request;

	ldap_request = p_new(request->pool, struct passdb_ldap_request, 1);
	ldap_request->callback.lookup_credentials = callback;

        ldap_lookup_pass(request, &ldap_request->request);
}

static void passdb_ldap_preinit(const char *args)
{
	passdb_ldap_conn = db_ldap_init(args);
	passdb_ldap_conn->pass_attr_map =
		hash_create(default_pool, passdb_ldap_conn->pool, 0, str_hash,
			    (hash_cmp_callback_t *)strcmp);

	db_ldap_set_attrs(passdb_ldap_conn, passdb_ldap_conn->set.pass_attrs,
                          &passdb_ldap_conn->pass_attr_names,
			  passdb_ldap_conn->pass_attr_map,
			  default_attr_map);
	passdb_ldap.cache_key = passdb_ldap_cache_key =
		auth_cache_parse_key(passdb_ldap_conn->set.pass_filter);
	passdb_ldap.default_pass_scheme =
		passdb_ldap_conn->set.default_pass_scheme;
}

static void passdb_ldap_init(const char *args __attr_unused__)
{
	(void)db_ldap_connect(passdb_ldap_conn);
}

static void passdb_ldap_deinit(void)
{
	db_ldap_unref(passdb_ldap_conn);
	i_free(passdb_ldap_cache_key);
}

struct passdb_module passdb_ldap = {
	"ldap",
	NULL, NULL, FALSE,

	passdb_ldap_preinit,
	passdb_ldap_init,
	passdb_ldap_deinit,

	ldap_verify_plain,
	ldap_lookup_credentials
};

#endif
