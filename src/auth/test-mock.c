/* Copyright (c) 2017-2018 Dovecot authors, see the included COPYING file */

#include "test-auth.h"
#include "auth-common.h"
#include "passdb.h"

struct auth_penalty *auth_penalty;
time_t process_start_time;
bool worker, worker_restart_request;
static struct passdb_module *mock_passdb_mod = NULL;
static pool_t mock_pool;

void auth_module_load(const char *names ATTR_UNUSED)
{
}
void auth_refresh_proctitle(void) {
}

static void passdb_mock_init(struct passdb_module *module ATTR_UNUSED)
{
}
static void passdb_mock_deinit(struct passdb_module *module ATTR_UNUSED)
{
}
static void passdb_mock_verify_plain(struct auth_request *request, const char *password ATTR_UNUSED,
				     verify_plain_callback_t *callback)
{
	callback(PASSDB_RESULT_OK, request);
}

static struct passdb_module_interface mock_interface = {
	.name = "mock",
	.init = passdb_mock_init,
	.deinit = passdb_mock_deinit,
	.verify_plain = passdb_mock_verify_plain,
};

static struct auth_passdb_settings set = {
	.name = "mock",
	.driver = "mock",
	.args = "",
	.default_fields = "",
	.override_fields = "",
	.mechanisms = "",
	.username_filter = "",
	.skip = "never",
	.result_success = "return-ok",
	.result_failure = "continue",
	.result_internalfail = "continue",
	.deny = FALSE,
	.pass = FALSE,
	.master = FALSE,
	.auth_verbose = "default"
};

void passdb_mock_mod_init(void)
{
	if (mock_passdb_mod != NULL)
		return;

	mock_pool = pool_allocfree_create("auth mock");

	passdb_register_module(&mock_interface);

	struct auth_passdb_settings set = {
		.name = "mock",
		.driver = "mock",
		.args = "",
		.default_fields = "",
		.override_fields = "",
		.mechanisms = "",
		.username_filter = "",

		.skip = "never",
		.result_success = "return-ok",
		.result_failure = "continue",
		.result_internalfail = "continue",

		.deny = FALSE,
		.pass = FALSE,
		.master = FALSE,
		.auth_verbose = "default"
	};
	mock_passdb_mod = passdb_preinit(mock_pool, &set);
	passdb_init(mock_passdb_mod);
}

void passdb_mock_mod_deinit(void)
{
	passdb_deinit(mock_passdb_mod);
	passdb_unregister_module(&mock_interface);
	pool_unref(&mock_pool);
}

struct auth_passdb *passdb_mock(void)
{
	struct auth_passdb *ret = i_new(struct auth_passdb, 1);
	ret->set = &set;
	ret->passdb = mock_passdb_mod;
	return ret;
}
