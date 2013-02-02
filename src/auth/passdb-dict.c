/* Copyright (c) 2013 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "passdb.h"

#include "str.h"
#include "var-expand.h"
#include "dict.h"
#include "password-scheme.h"
#include "auth-cache.h"
#include "db-dict.h"

#include <stdlib.h>
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
			struct dict_connection *conn, const char *result)
{
	struct db_dict_value_iter *iter;
	const char *key, *value, *error;

	iter = db_dict_value_iter_init(conn, result);
	while (db_dict_value_iter_next(iter, &key, &value)) {
		if (value != NULL) {
			auth_request_set_field(auth_request, key, value,
					       conn->set.default_pass_scheme);
		}
	}
	if (db_dict_value_iter_deinit(&iter, &error) < 0) {
		auth_request_log_error(auth_request, "dict",
			"Value '%s' not in valid %s format: %s",
			result, conn->set.value_format, error);
		return -1;
	}
	return 0;
}

static enum passdb_result
passdb_dict_lookup_key(struct auth_request *auth_request,
		       struct dict_passdb_module *module, const char *key)
{
	const char *value;
	int ret;

	auth_request_log_debug(auth_request, "dict", "lookup %s", key);
	ret = dict_lookup(module->conn->dict, pool_datastack_create(),
			  key, &value);
	if (ret < 0) {
		auth_request_log_error(auth_request, "dict", "Lookup failed");
		return PASSDB_RESULT_INTERNAL_FAILURE;
	} else if (ret == 0) {
		auth_request_log_info(auth_request, "dict", "unknown user");
		return PASSDB_RESULT_USER_UNKNOWN;
	} else {
		auth_request_log_debug(auth_request, "dict",
				       "result: %s", value);
		if (dict_query_save_results(auth_request, module->conn, value) < 0)
			return PASSDB_RESULT_INTERNAL_FAILURE;

		if (auth_request->passdb_password == NULL &&
		    !auth_fields_exists(auth_request->extra_fields, "nopassword")) {
			auth_request_log_info(auth_request, "dict",
				"No password returned (and no nopassword)");
			return PASSDB_RESULT_PASSWORD_MISMATCH;
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
	string_t *key;
	const char *password = NULL, *scheme = NULL;
	enum passdb_result passdb_result;
	int ret;

	key = t_str_new(512);
	str_append(key, DICT_PATH_SHARED);
	var_expand(key, module->conn->set.password_key,
		   auth_request_get_var_expand_table(auth_request, NULL));

	if (*module->conn->set.password_key == '\0') {
		auth_request_log_error(auth_request, "dict",
				       "password_key not specified");
		passdb_result = PASSDB_RESULT_INTERNAL_FAILURE;
	} else {
		passdb_result = passdb_dict_lookup_key(auth_request, module,
						       str_c(key));
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
					password, scheme, "dict");
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
	module->module.cache_key =
		auth_cache_parse_key(pool, conn->set.password_key);
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
