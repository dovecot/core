/* Copyright (c) 2017-2018 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "passdb.h"
#include "db-oauth2.h"

struct oauth2_passdb_module {
	struct passdb_module module;
	struct db_oauth2 *db;
};

static void
oauth2_verify_plain_continue(struct db_oauth2_request *req,
			     enum passdb_result result, const char *error,
			     struct auth_request *request)
{
	if (result == PASSDB_RESULT_INTERNAL_FAILURE)
		auth_request_log_error(request, AUTH_SUBSYS_DB, "oauth2 failed: %s",
				       error);
	else if (result != PASSDB_RESULT_OK)
		auth_request_log_info(request, AUTH_SUBSYS_DB, "oauth2 failed: %s",
				      error);
	else {
		auth_request_set_field(request, "token", req->token, "PLAIN");
	}
	req->verify_callback(result, request);
	auth_request_unref(&request);
}

static void
oauth2_verify_plain(struct auth_request *request, const char *password,
		    verify_plain_callback_t *callback)
{
	struct oauth2_passdb_module *module =
		(struct oauth2_passdb_module *)request->passdb->passdb;
	struct db_oauth2_request *req =
		p_new(request->pool, struct db_oauth2_request, 1);
	req->pool = request->pool;
	req->verify_callback = callback;

	auth_request_ref(request);

	db_oauth2_lookup(module->db, req, password, request, oauth2_verify_plain_continue, request);
}

static struct passdb_module *
oauth2_preinit(pool_t pool, const char *args)
{
	struct oauth2_passdb_module *module;

	module = p_new(pool, struct oauth2_passdb_module, 1);
	module->db = db_oauth2_init(args);
	module->module.default_pass_scheme = "PLAIN";

	if (db_oauth2_uses_password_grant(module->db)) {
		module->module.default_cache_key = "%u";
	} else {
		module->module.default_cache_key = "%u%w";
	}

	return &module->module;
}

static void oauth2_deinit(struct passdb_module *passdb)
{
	struct oauth2_passdb_module *module = (struct oauth2_passdb_module *)passdb;
	db_oauth2_unref(&module->db);
}

struct passdb_module_interface passdb_oauth2 = {
	"oauth2",

	oauth2_preinit,
	NULL,
	oauth2_deinit,

	oauth2_verify_plain,
	NULL,
	NULL
};
