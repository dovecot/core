/* Copyright (c) 2024 Dovecot authors, see the included COPYING file */

#include "test-auth.h"
#include "auth-common.h"
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

struct auth_settings test_auth_set;
static struct mechanisms_register *mech_reg;

void test_auth_init(void)
{
	const char *const protocols[] = {NULL};
	process_start_time = time(NULL);

	/* Copy default settings */
	test_auth_set = *(const struct auth_settings *)auth_setting_parser_info.defaults;
	test_auth_set.pool = pool_alloconly_create("test settings", 128);
	test_auth_set.base_dir = ".";
	test_auth_set.mechanisms = "plain";
	global_auth_settings = &test_auth_set;
	memset((&test_auth_set)->username_chars_map, 1,
	       sizeof((&test_auth_set)->username_chars_map));
	test_auth_set.username_format = "";

	p_array_init(&test_auth_set.parsed_passdbs, test_auth_set.pool, 2);
	struct auth_passdb_settings *mock_set = t_new(struct auth_passdb_settings, 1);
	*mock_set = mock_passdb_set;
	const struct auth_passdb_settings *const_mock_set = mock_set;
	array_push_back(&test_auth_set.parsed_passdbs, &const_mock_set);
	mock_set = p_new(test_auth_set.pool, struct auth_passdb_settings, 1);
	*mock_set = mock_passdb_set;
	mock_set->master = TRUE;
	const_mock_set = mock_set;
	array_push_back(&test_auth_set.parsed_passdbs, &const_mock_set);
	p_array_init(&test_auth_set.parsed_userdbs, test_auth_set.pool, 1);

	/* For tests of digest-md5. */
	test_auth_set.realms_arr = t_strsplit_spaces("example.com ", " ");
	/* For tests of mech-anonymous. */
	test_auth_set.anonymous_username = "anonuser";

	mech_init(global_auth_settings);
	mech_reg = mech_register_init(global_auth_settings);
	passdbs_init();
	userdbs_init();
	passdb_mock_mod_init();
	password_schemes_init();
	password_schemes_allow_weak(TRUE);

	auths_preinit(&test_auth_set, mech_reg, protocols);
	auths_init();
	auth_token_init();

	auth_penalty = auth_penalty_init("missing");
}

void test_auth_deinit(void)
{
	auth_penalty_deinit(&auth_penalty);
	mech_otp_deinit();
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
	pool_unref(&test_auth_set.pool);
	i_unlink_if_exists("auth-token-secret.dat");
}
