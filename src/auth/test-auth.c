/* Copyright (c) 2024 Dovecot authors, see the included COPYING file */

#include "test-auth.h"
#include "auth-common.h"
#include "settings.h"
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

static const char *const settings[] = {
	"base_dir", ".",
	"auth_mechanisms", "plain xoauth2",
	"auth_username_chars", "",
	"auth_username_format", "",
	/* For tests of digest-md5. */
	"auth_realms", "example.com",
	/* For tests of mech-anonymous. */
	"auth_anonymous_username", "anonuser",
	/* For oauth2 tests */
	"oauth2_introspection_mode", "auth",
	"oauth2_tokeninfo_url", "http://localhost",
	"oauth2_client_id", "foo",
	"oauth2_client_secret", "foo",
	"oauth2_use_worker", "no",

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

	settings_simple_init(&simple_set, settings);
	global_auth_settings = settings_get_or_fatal(simple_set.event,
						     &auth_setting_parser_info);
	/* this is needed to get oauth2 initialized */
	auth_event = simple_set.event;
	mech_init(global_auth_settings);
	mech_reg = mech_register_init(global_auth_settings);
	passdbs_init();
	userdbs_init();
	passdb_mock_mod_init();
	password_schemes_register_all();
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
}
