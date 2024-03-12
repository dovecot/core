/* Copyright (c) 2024 Dovecot authors, see the included COPYING file */

#include "test-auth.h"
#include "ostream.h"
#include "auth-common.h"
#include "settings.h"
#include "settings-parser.h"
#include "auth-settings.h"
#include "auth-token.h"
#include "auth-penalty.h"
#include "mech.h"
#include "otp.h"
#include "mech-otp-common.h"
#include "db-oauth2.h"
#include "passdb.h"
#include "userdb.h"

#include <time.h>

#define TEST_OAUTH2_CONFIG_FILE "test-oauth2-config"

static const char *const settings[] = {
	"base_dir", ".",
	"auth_mechanisms", "plain",
	"auth_username_chars", "",
	"auth_username_format", "",
	/* For tests of digest-md5. */
	"auth_realms", "example.com",
	/* For tests of mech-anonymous. */
	"auth_anonymous_username", "anonuser",
	/* For oauth2 tests */
	"auth_oauth2_config_file", TEST_OAUTH2_CONFIG_FILE,

	"passdb", "mock1 mock2",
	"passdb/mock1/name", "mock1",
	"passdb/mock1/driver", "mock",
	"passdb/mock2/name", "mock1",
	"passdb/mock2/driver", "mock",
	"passdb/mock2/master", "yes",

	NULL
};

static struct mechanisms_register *mech_reg;
static struct settings_simple simple_set;

void test_auth_init(void)
{
	const char *const protocols[] = {NULL};
	process_start_time = time(NULL);

	/* create oauth2 config file */
	struct ostream *os =
		o_stream_create_file(TEST_OAUTH2_CONFIG_FILE, 0, 0600, 0);
	o_stream_nsend_str(os, "tokeninfo_url = http://localhost\nclient_id=foo\nblocking=no\n");
	test_assert(o_stream_finish(os) == 1);
	o_stream_unref(&os);

	settings_simple_init(&simple_set, settings);
	global_auth_settings = settings_get_or_fatal(simple_set.event,
						     &auth_setting_parser_info);

	mech_init(global_auth_settings);
	mech_reg = mech_register_init(global_auth_settings);
	passdbs_init();
	userdbs_init();
	passdb_mock_mod_init();
	password_schemes_init();
	password_schemes_allow_weak(TRUE);

	auths_preinit(simple_set.event, global_auth_settings, mech_reg, protocols);
	auths_init();
	auth_token_init();

	auth_penalty = auth_penalty_init("missing");
}

void test_auth_deinit(void)
{
	auth_penalty_deinit(&auth_penalty);
	mech_otp_deinit();
	db_oauth2_deinit();
	auths_deinit();
	auth_token_deinit();
	password_schemes_deinit();
	passdb_mock_mod_deinit();
	passdbs_deinit();
	userdbs_deinit();
	event_unref(&auth_event);
	mech_deinit(global_auth_settings);
	mech_register_deinit(&mech_reg);
	auths_free();
	settings_free(global_auth_settings);
	settings_simple_deinit(&simple_set);
	i_unlink_if_exists("auth-token-secret.dat");
	i_unlink_if_exists(TEST_OAUTH2_CONFIG_FILE);
}
