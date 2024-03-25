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
		e_error(authdb_event(request), "oauth2 failed: %s",
			error);
	else if (result != PASSDB_RESULT_OK)
		e_info(authdb_event(request), "oauth2 failed: %s",
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
	const char *error;

	module = p_new(pool, struct oauth2_passdb_module, 1);
	if (db_oauth2_init(args, &module->db, &error) < 0)
		i_fatal("%s", error);
	module->module.default_pass_scheme = "PLAIN";

	if (db_oauth2_uses_password_grant(module->db)) {
		module->module.default_cache_key = "%u";
	} else {
		module->module.default_cache_key = "%u%w";
	}

	return &module->module;
}

static void oauth2_deinit(struct passdb_module *passdb ATTR_UNUSED)
{
}

struct passdb_module_interface passdb_oauth2 = {
	.name = "oauth2",

	.preinit_legacy = oauth2_preinit,
	.deinit = oauth2_deinit,
	.verify_plain = oauth2_verify_plain,
};
