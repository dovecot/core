/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "passdb.h"

#include "array.h"
#include "str.h"
#include "var-expand.h"
#include "dict.h"
#include "password-scheme.h"
#include "auth-cache.h"
#include "db-dict.h"

#include <string.h>

struct dict_passdb_module {
	struct passdb_module module;

	struct dict_connection *conn;
};

struct passdb_dict_request {
	struct auth_request *auth_request;
	union {
		verify_plain_callback_t *verify_plain;
                lookup_credentials_callback_t *lookup_credentials;
	} callback;
};

static int
dict_query_save_results(struct auth_request *auth_request,
			struct dict_connection *conn,
			struct db_dict_value_iter *iter)
{
	const char *key, *value, *error;

	while (db_dict_value_iter_next(iter, &key, &value)) {
		if (value != NULL) {
			auth_request_set_field(auth_request, key, value,
					       conn->set.default_pass_scheme);
		}
	}
	if (db_dict_value_iter_deinit(&iter, &error) < 0) {
		e_error(authdb_event(auth_request), "%s", error);
		return -1;
	}
	return 0;
}

static enum passdb_result
passdb_dict_lookup_key(struct auth_request *auth_request,
		       struct dict_passdb_module *module)
{
	struct db_dict_value_iter *iter;
	int ret;

	ret = db_dict_value_iter_init(module->conn, auth_request,
				      &module->conn->set.passdb_fields,
				      &module->conn->set.parsed_passdb_objects,
				      &iter);
	if (ret < 0)
		return PASSDB_RESULT_INTERNAL_FAILURE;
	else if (ret == 0) {
		auth_request_log_unknown_user(auth_request, AUTH_SUBSYS_DB);
		return PASSDB_RESULT_USER_UNKNOWN;
	} else {
		if (dict_query_save_results(auth_request, module->conn, iter) < 0)
			return PASSDB_RESULT_INTERNAL_FAILURE;

		if (auth_request->passdb_password == NULL &&
		    !auth_fields_exists(auth_request->extra_fields, "nopassword")) {
			return auth_request_password_missing(auth_request);
		} else {
			return PASSDB_RESULT_OK;
		}
	}
}

static void passdb_dict_lookup_pass(struct passdb_dict_request *dict_request)
{
	struct auth_request *auth_request = dict_request->auth_request;
	struct passdb_module *_module = auth_request->passdb->passdb;
	struct dict_passdb_module *module =
		(struct dict_passdb_module *)_module;
	const char *password = NULL, *scheme = NULL;
	enum passdb_result passdb_result;
	int ret;

	if (array_count(&module->conn->set.passdb_fields) == 0 &&
	    array_count(&module->conn->set.parsed_passdb_objects) == 0) {
		e_error(authdb_event(auth_request),
			"No passdb_objects or passdb_fields specified");
		passdb_result = PASSDB_RESULT_INTERNAL_FAILURE;
	} else {
		passdb_result = passdb_dict_lookup_key(auth_request, module);
	}

	if (passdb_result == PASSDB_RESULT_OK) {
		/* passdb_password may change on the way,
		   so we'll need to strdup. */
		password = t_strdup(auth_request->passdb_password);
		scheme = password_get_scheme(&password);
		/* auth_request_set_field() sets scheme */
		i_assert(password == NULL || scheme != NULL);
	}

	if (auth_request->credentials_scheme != NULL) {
		passdb_handle_credentials(passdb_result, password, scheme,
			dict_request->callback.lookup_credentials,
			auth_request);
	} else {
		if (password != NULL) {
			ret = auth_request_password_verify(auth_request,
					auth_request->mech_password,
					password, scheme, AUTH_SUBSYS_DB);
			passdb_result = ret > 0 ? PASSDB_RESULT_OK :
				PASSDB_RESULT_PASSWORD_MISMATCH;
		}

		dict_request->callback.verify_plain(passdb_result,
						    auth_request);
	}
}

static void dict_verify_plain(struct auth_request *request,
			      const char *password ATTR_UNUSED,
			      verify_plain_callback_t *callback)
{
	struct passdb_dict_request *dict_request;

	dict_request = p_new(request->pool, struct passdb_dict_request, 1);
	dict_request->auth_request = request;
	dict_request->callback.verify_plain = callback;

	passdb_dict_lookup_pass(dict_request);
}

static void dict_lookup_credentials(struct auth_request *request,
				    lookup_credentials_callback_t *callback)
{
	struct passdb_dict_request *dict_request;

	dict_request = p_new(request->pool, struct passdb_dict_request, 1);
	dict_request->auth_request = request;
	dict_request->callback.lookup_credentials = callback;

        passdb_dict_lookup_pass(dict_request);
}

static struct passdb_module *
passdb_dict_preinit(pool_t pool, const char *args)
{
	struct dict_passdb_module *module;
	struct dict_connection *conn;

	module = p_new(pool, struct dict_passdb_module, 1);
	module->conn = conn = db_dict_init(args);

	module->module.blocking = TRUE;
	module->module.default_cache_key = auth_cache_parse_key(pool,
		db_dict_parse_cache_key(&conn->set.keys, &conn->set.passdb_fields,
					&conn->set.parsed_passdb_objects));
	module->module.default_pass_scheme = conn->set.default_pass_scheme;
	return &module->module;
}

static void passdb_dict_deinit(struct passdb_module *_module)
{
	struct dict_passdb_module *module =
		(struct dict_passdb_module *)_module;

	db_dict_unref(&module->conn);
}

struct passdb_module_interface passdb_dict = {
	"dict",

	passdb_dict_preinit,
	NULL,
	passdb_dict_deinit,
       
	dict_verify_plain,
	dict_lookup_credentials,
	NULL
};
