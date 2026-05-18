/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "str.h"
#include "strfuncs.h"
#include "settings.h"
#include "test-common.h"
#include "client-auth-settings.h"
#include "dsasl-client.h"

#include <unistd.h>

static bool debug = FALSE;
static struct settings_root *set_root = NULL;

static struct dsasl_client_session *
test_init_sasl_session_params(struct dsasl_client *client,
			      const struct dsasl_client_parameters *params,
			      const char *const *settings, const char **error_r)
{
	struct event *event;
	struct dsasl_client_session *session;

	settings_root_deinit(&set_root);
	set_root = settings_root_init();
	for (unsigned int i = 0; settings[i] != NULL; i++) {
		const char *key, *value;
		t_split_key_value_eq(settings[i], &key, &value);
		settings_root_override(set_root, key, value,
				       SETTINGS_OVERRIDE_TYPE_CODE);
	}
	event = event_create(NULL);
	event_set_ptr(event, SETTINGS_EVENT_ROOT, set_root);

	if (dsasl_client_session_create_auto(client, event, params,
					     &session, error_r) < 0)
		session = NULL;

	event_unref(&event);

	return session;
}

static struct dsasl_client_session *
test_init_sasl_session(struct dsasl_client *client, const char *const *settings,
		       const char **error_r)
{
	struct dsasl_client_parameters params = {
	};

	return test_init_sasl_session_params(client, &params, settings,
					     error_r);
}

static void test_sasl_client_login(void)
{
	static const char *const sasl_empty_set[] = {
		"client_auth_mechanism=LOGIN",
		NULL
	};
	static const char *const sasl_no_password_set[] = {
		"client_auth_mechanism=LOGIN",
		"client_auth_authid=testuser",
		NULL
	};
	static const char *const sasl_set[] = {
		"client_auth_mechanism=LOGIN",
		"client_auth_authid=testuser",
		"client_auth_password=testpassword",
		NULL
	};
	struct dsasl_client *client;
	struct dsasl_client_session *session;
	const char *error;

	test_begin("sasl client LOGIN");

	client = dsasl_client_create(NULL);

	string_t *input = t_str_new(64);
	string_t *output_s = t_str_new(64);
	const unsigned char *output;
	size_t olen;

	session = test_init_sasl_session(client, sasl_set, &error);
	i_assert(session != NULL);

	/* Any input is valid */
	str_append(input, "Username:");
	test_assert(dsasl_client_session_input(session, input->data, input->used, &error) == DSASL_CLIENT_RESULT_OK);
	test_assert(dsasl_client_session_output(session, &output, &olen, &error) == DSASL_CLIENT_RESULT_OK);
	/* see what we got */
	str_append_data(output_s, output, olen);
	test_assert_strcmp(str_c(output_s), "testuser");

	str_truncate(input, 0);
	str_truncate(output_s, 0);

	str_append(input, "Password:");
	test_assert(dsasl_client_session_input(session, input->data, input->used, &error) == DSASL_CLIENT_RESULT_OK);
	test_assert(dsasl_client_session_output(session, &output, &olen, &error) == DSASL_CLIENT_RESULT_OK);
	str_append_data(output_s, output, olen);
	test_assert_strcmp(str_c(output_s), "testpassword");

	/* there should be no results to collect, we can reuse error here */
	test_assert(dsasl_client_session_get_result(session, "parameter", &error, &error) == 0);

	dsasl_client_session_destroy(&session);
	test_assert(session == NULL);

	/* server sends input after password */
	session = test_init_sasl_session(client, sasl_set, &error);
	i_assert(session != NULL);
	test_assert(dsasl_client_session_input(session, uchar_empty_ptr, 0, &error) == DSASL_CLIENT_RESULT_OK);
	test_assert(dsasl_client_session_output(session, &output, &olen, &error) == DSASL_CLIENT_RESULT_OK);
	test_assert(dsasl_client_session_input(session, uchar_empty_ptr, 0, &error) == DSASL_CLIENT_RESULT_OK);
	test_assert(dsasl_client_session_output(session, &output, &olen, &error) == DSASL_CLIENT_RESULT_OK);
	test_assert(dsasl_client_session_input(session, uchar_empty_ptr, 0, &error) == DSASL_CLIENT_RESULT_ERR_PROTOCOL);
	test_assert_strcmp(error, "Server didn't finish authentication");
	dsasl_client_session_destroy(&session);
	test_assert(session == NULL);

	/* missing username & password */
	session = test_init_sasl_session(client, sasl_empty_set, &error);
	i_assert(session == NULL);
	test_assert(str_begins_with(error, "No authentication or authorization identity configured for the LOGIN mechanism"));

	/* missing password */
	session = test_init_sasl_session(client, sasl_no_password_set, &error);
	i_assert(session == NULL);
	test_assert_strcmp(error, "No password configured (client_auth_password setting)");

	/* unexpected NUL byte in input */
	session = test_init_sasl_session(client, sasl_set, &error);
	test_assert(session != NULL);
	str_truncate(input, 0);
	str_append_data(input, "unexpected\0", 11);
	test_assert(dsasl_client_session_input(session, input->data, input->used, &error) == DSASL_CLIENT_RESULT_ERR_PROTOCOL);
	test_assert_strcmp(error, "Unexpected NUL in input data");
	dsasl_client_session_destroy(&session);
	test_assert(session == NULL);

	dsasl_client_unref(&client);
	test_assert(client == NULL);

	test_end();
}

static void test_sasl_client_plain(void)
{
	static const char *const sasl_empty_set[] = {
		"client_auth_mechanism=PLAIN",
		NULL
	};
	static const char *const sasl_no_password_set[] = {
		"client_auth_mechanism=PLAIN",
		"client_auth_authid=testuser",
		NULL
	};
	static const char *const sasl_set[] = {
		"client_auth_mechanism=PLAIN",
		"client_auth_authid=testuser",
		"client_auth_password=testpassword",
		NULL
	};
	static const char *const sasl_master_set[] = {
		"client_auth_mechanism=PLAIN",
		"client_auth_authzid=testuser",
		"client_auth_authid=masteruser",
		"client_auth_password=masterpassword",
		NULL
	};
	struct dsasl_client *client;
	struct dsasl_client_session *session;
	const char *error;

	test_begin("sasl client PLAIN");

	client = dsasl_client_create(NULL);

	const unsigned char *output;
	size_t olen;

	session = test_init_sasl_session(client, sasl_set, &error);
	i_assert(session != NULL);
	test_assert(dsasl_client_session_input(session, uchar_empty_ptr, 0, &error) == DSASL_CLIENT_RESULT_OK);
	test_assert(dsasl_client_session_output(session, &output, &olen, &error) == DSASL_CLIENT_RESULT_OK);
	const unsigned char expected[] = "\0testuser\0testpassword";
	/* there is no NUL byte at the end */
	test_assert(olen == sizeof(expected) - 1);
	test_assert(memcmp(output, expected, I_MIN(sizeof(expected) - 1, olen)) == 0);
	dsasl_client_session_destroy(&session);
	test_assert(session == NULL);

	session = test_init_sasl_session(client, sasl_master_set, &error);
	i_assert(session != NULL);
	test_assert(dsasl_client_session_input(session, uchar_empty_ptr, 0, &error) == DSASL_CLIENT_RESULT_OK);
	test_assert(dsasl_client_session_output(session, &output, &olen, &error) == DSASL_CLIENT_RESULT_OK);
	const unsigned char expected_master[] =
		"testuser\0masteruser\0masterpassword";
	/* there is no NUL byte at the end */
	test_assert(olen == sizeof(expected_master) - 1);
	test_assert(memcmp(output, expected_master,
			   I_MIN(sizeof(expected_master) - 1, olen)) == 0);
	dsasl_client_session_destroy(&session);
	test_assert(session == NULL);

	/* unexpected initial response */
	const unsigned char input[] = "ir";
	session = test_init_sasl_session(client, sasl_set, &error);
	i_assert(session != NULL);
	test_assert(dsasl_client_session_input(session, input, sizeof(input)-1, &error) == DSASL_CLIENT_RESULT_ERR_PROTOCOL);
	test_assert_strcmp(error, "Server sent non-empty initial response");
	dsasl_client_session_destroy(&session);
	test_assert(session == NULL);

	/* server sends input after response */
	session = test_init_sasl_session(client, sasl_set, &error);
	i_assert(session != NULL);
	test_assert(dsasl_client_session_input(session, uchar_empty_ptr, 0, &error) == DSASL_CLIENT_RESULT_OK);
	test_assert(dsasl_client_session_output(session, &output, &olen, &error) == DSASL_CLIENT_RESULT_OK);
	test_assert(dsasl_client_session_input(session, uchar_empty_ptr, 0, &error) == DSASL_CLIENT_RESULT_ERR_PROTOCOL);
	test_assert_strcmp(error, "Server didn't finish authentication");
	dsasl_client_session_destroy(&session);
	test_assert(session == NULL);

	/* missing username & password */
	session = test_init_sasl_session(client, sasl_empty_set, &error);
	i_assert(session == NULL);
	test_assert(str_begins_with(error, "No authentication or authorization identity configured for the PLAIN mechanism"));

	/* missing password */
	session = test_init_sasl_session(client, sasl_no_password_set, &error);
	i_assert(session == NULL);
	test_assert_strcmp(error, "No password configured (client_auth_password setting)");

	/* unexpected NUL byte in input */
	session = test_init_sasl_session(client, sasl_set, &error);
	i_assert(session != NULL);
	const unsigned char input2[] = "unexpected\0";
	test_assert(dsasl_client_session_input(session, input2, sizeof(input2), &error) == DSASL_CLIENT_RESULT_ERR_PROTOCOL);
	test_assert_strcmp(error, "Unexpected NUL in input data");
	dsasl_client_session_destroy(&session);
	test_assert(session == NULL);

	dsasl_client_unref(&client);
	test_assert(client == NULL);

	test_end();
}

static void test_sasl_client_external(void)
{
	static const char *const sasl_set[] = {
		"client_auth_mechanism=EXTERNAL",
		"client_auth_authid=testuser",
		"client_auth_password=testpassword",
		NULL
	};
	static const char *const sasl_master_set[] = {
		"client_auth_mechanism=EXTERNAL",
		"client_auth_authzid=testuser",
		"client_auth_authid=masteruser",
		"client_auth_password=masterpassword",
		NULL
	};
	struct dsasl_client *client;
	struct dsasl_client_session *session;
	const char *error;

	test_begin("sasl client EXTERNAL");

	client = dsasl_client_create(NULL);

	const unsigned char *output;
	size_t olen;

	session = test_init_sasl_session(client, sasl_set, &error);
	i_assert(session != NULL);
	test_assert(dsasl_client_session_input(session, uchar_empty_ptr, 0, &error) == DSASL_CLIENT_RESULT_OK);
	test_assert(dsasl_client_session_output(session, &output, &olen, &error) == DSASL_CLIENT_RESULT_OK);
	const unsigned char expected[] = "testuser";
	/* there is no NUL byte at the end */
	test_assert(olen == sizeof(expected) - 1);
	test_assert(memcmp(output, expected, I_MIN(sizeof(expected) - 1, olen)) == 0);
	dsasl_client_session_destroy(&session);
	test_assert(session == NULL);

	session = test_init_sasl_session(client, sasl_master_set, &error);
	i_assert(session != NULL);
	test_assert(dsasl_client_session_input(session, uchar_empty_ptr, 0, &error) == DSASL_CLIENT_RESULT_OK);
	test_assert(dsasl_client_session_output(session, &output, &olen, &error) == DSASL_CLIENT_RESULT_OK);
	const unsigned char expected_master[] =	"testuser";
	/* there is no NUL byte at the end */
	test_assert(olen == sizeof(expected_master) - 1);
	test_assert(memcmp(output, expected_master,
			   I_MIN(sizeof(expected_master) - 1, olen)) == 0);
	dsasl_client_session_destroy(&session);
	test_assert(session == NULL);

	/* unexpected NUL byte in input */
	session = test_init_sasl_session(client, sasl_set, &error);
	i_assert(session != NULL);
	const unsigned char input2[] = "unexpected\0";
	test_assert(dsasl_client_session_input(session, input2, sizeof(input2), &error) == DSASL_CLIENT_RESULT_ERR_PROTOCOL);
	test_assert_strcmp(error, "Unexpected NUL in input data");
	dsasl_client_session_destroy(&session);
	test_assert(session == NULL);

	dsasl_client_unref(&client);
	test_assert(client == NULL);

	test_end();
}

static void test_sasl_client_oauthbearer(void)
{
	static const char *const sasl_empty_set[] = {
		"client_auth_mechanism=OAUTHBEARER",
		NULL
	};
	static const char *const sasl_no_password_set[] = {
		"client_auth_mechanism=OAUTHBEARER",
		"client_auth_authid=testuser",
		NULL
	};
	static const char *const sasl_set[] = {
		"client_auth_mechanism=OAUTHBEARER",
		"client_auth_authid=testuser",
		"client_auth_password=testpassword",
		NULL
	};
	struct dsasl_client *client;
	struct dsasl_client_session *session;
	const char *error;
	const char *value;

	test_begin("sasl client OAUTHBEARER");

	client = dsasl_client_create(NULL);

	string_t *input = t_str_new(64);
	const unsigned char *output;
	size_t olen;

	session = test_init_sasl_session(client, sasl_set, &error);
	i_assert(session != NULL);
	test_assert(dsasl_client_session_input(session, uchar_empty_ptr, 0, &error) == DSASL_CLIENT_RESULT_OK);
	test_assert(dsasl_client_session_output(session, &output, &olen, &error) == DSASL_CLIENT_RESULT_OK);
	test_assert(dsasl_client_session_input(session, uchar_empty_ptr, 0, &error) == DSASL_CLIENT_RESULT_OK);

	const unsigned char expected[] = "n,a=testuser,\1"
		"auth=Bearer testpassword\1\1";
	/* there is no NUL byte at the end */
	test_assert(olen == sizeof(expected) - 1);
	test_assert(memcmp(output, expected, I_MIN(sizeof(expected) - 1, olen)) == 0);
	test_assert(dsasl_client_session_get_result(session, "status", &value, &error) == 1);
	test_assert_strcmp(value, "");

	dsasl_client_session_destroy(&session);
	test_assert(session == NULL);

	/* with host & port set */
	struct dsasl_client_parameters params = {
		.host = "example.com",
		.port = 143,
	};
	session = test_init_sasl_session_params(client, &params, sasl_set, &error);
	i_assert(session != NULL);

	test_assert(dsasl_client_session_input(session, uchar_empty_ptr, 0, &error) == DSASL_CLIENT_RESULT_OK);
	test_assert(dsasl_client_session_output(session, &output, &olen, &error) == DSASL_CLIENT_RESULT_OK);
	test_assert(dsasl_client_session_input(session, uchar_empty_ptr, 0, &error) == DSASL_CLIENT_RESULT_OK);

	const unsigned char expected_h_p[] = "n,a=testuser,\1"
		"host=example.com\1"
		"port=143\1"
		"auth=Bearer testpassword\1\1";
	/* there is no NUL byte at the end */
	test_assert(olen == sizeof(expected_h_p) - 1);
	test_assert(memcmp(output, expected_h_p,
			   I_MIN(sizeof(expected_h_p) - 1, olen)) == 0);

	dsasl_client_session_destroy(&session);
	test_assert(session == NULL);

	/* test error response */
	session = test_init_sasl_session(client, sasl_set, &error);
	i_assert(session != NULL);
	test_assert(dsasl_client_session_input(session, uchar_empty_ptr, 0, &error) == DSASL_CLIENT_RESULT_OK);
	test_assert(dsasl_client_session_output(session, &output, &olen, &error) == DSASL_CLIENT_RESULT_OK);
	test_assert(dsasl_client_session_input(session, uchar_empty_ptr, 0, &error) == DSASL_CLIENT_RESULT_OK);
	str_append(input, "{\"status\":\"401\",\"schemes\":\"bearer\",\"scope\":\"mail\"}");
	test_assert(dsasl_client_session_input(session, input->data, input->used, &error) == DSASL_CLIENT_RESULT_AUTH_FAILED);
	test_assert_strcmp(error, "Failed to authenticate: 401");
	test_assert(dsasl_client_session_get_result(session, "status", &value, &error) == 1);
	test_assert_strcmp(value, "401");
	dsasl_client_session_destroy(&session);
	test_assert(session == NULL);

	/* missing username & password */
	session = test_init_sasl_session(client, sasl_empty_set, &error);
	i_assert(session == NULL);
	test_assert(str_begins_with(error, "No authentication or authorization identity configured for the OAUTHBEARER mechanism"));

	/* missing password */
	session = test_init_sasl_session(client, sasl_no_password_set, &error);
	i_assert(session == NULL);
	test_assert_strcmp(error, "No password configured (client_auth_password setting)");

	/* unexpected NUL byte in input */
	session = test_init_sasl_session(client, sasl_set, &error);
	i_assert(session != NULL);
	const unsigned char input2[] = "unexpected\0";
	test_assert(dsasl_client_session_input(session, input2, sizeof(input2), &error) == DSASL_CLIENT_RESULT_ERR_PROTOCOL);
	test_assert_strcmp(error, "Unexpected NUL in input data");
	dsasl_client_session_destroy(&session);
	test_assert(session == NULL);

	dsasl_client_unref(&client);
	test_assert(client == NULL);

	test_end();
}

static void test_sasl_client_xoauth2(void)
{
	static const char *const sasl_empty_set[] = {
		"client_auth_mechanism=XOAUTH2",
		NULL
	};
	static const char *const sasl_no_password_set[] = {
		"client_auth_mechanism=XOAUTH2",
		"client_auth_authid=testuser",
		NULL
	};
	static const char *const sasl_set[] = {
		"client_auth_mechanism=XOAUTH2",
		"client_auth_authid=testuser",
		"client_auth_password=testpassword",
		NULL
	};
	struct dsasl_client *client;
	struct dsasl_client_session *session;
	const char *error;

	test_begin("sasl client XOAUTH2");

	client = dsasl_client_create(NULL);

	string_t *input = t_str_new(64);
	const unsigned char *output;
	size_t olen;

	session = test_init_sasl_session(client, sasl_set, &error);
	i_assert(session != NULL);
	test_assert(dsasl_client_session_input(session, uchar_empty_ptr, 0, &error) == DSASL_CLIENT_RESULT_OK);
	test_assert(dsasl_client_session_output(session, &output, &olen, &error) == DSASL_CLIENT_RESULT_OK);
	test_assert(dsasl_client_session_input(session, uchar_empty_ptr, 0, &error) == DSASL_CLIENT_RESULT_OK);

	const unsigned char expected[] = "user=testuser\1auth=Bearer testpassword\1\1";
	/* there is no NUL byte at the end */
	test_assert(olen == sizeof(expected) - 1);
	test_assert(memcmp(output, expected, I_MIN(sizeof(expected) - 1, olen)) == 0);

	dsasl_client_session_destroy(&session);
	test_assert(session == NULL);

	/* test error response */
	session = test_init_sasl_session(client, sasl_set, &error);
	i_assert(session != NULL);
	test_assert(dsasl_client_session_input(session, uchar_empty_ptr, 0, &error) == DSASL_CLIENT_RESULT_OK);
	test_assert(dsasl_client_session_output(session, &output, &olen, &error) == DSASL_CLIENT_RESULT_OK);
	test_assert(dsasl_client_session_input(session, uchar_empty_ptr, 0, &error) == DSASL_CLIENT_RESULT_OK);
	str_append(input, "{\"status\":\"401\",\"schemes\":\"bearer\",\"scope\":\"mail\"}");
	test_assert(dsasl_client_session_input(session, input->data, input->used, &error) == DSASL_CLIENT_RESULT_AUTH_FAILED);
	test_assert_strcmp(error, "Failed to authenticate: 401");
	dsasl_client_session_destroy(&session);
	test_assert(session == NULL);

	/* missing username & password */
	session = test_init_sasl_session(client, sasl_empty_set, &error);
	i_assert(session == NULL);
	test_assert(str_begins_with(error, "No authentication or authorization identity configured for the XOAUTH2 mechanism"));

	/* missing password */
	session = test_init_sasl_session(client, sasl_no_password_set, &error);
	i_assert(session == NULL);
	test_assert_strcmp(error, "No password configured (client_auth_password setting)");

	/* unexpected NUL byte in input */
	session = test_init_sasl_session(client, sasl_set, &error);
	i_assert(session != NULL);
	const unsigned char input2[] = "unexpected\0";
	test_assert(dsasl_client_session_input(session, input2, sizeof(input2), &error) == DSASL_CLIENT_RESULT_ERR_PROTOCOL);
	test_assert_strcmp(error, "Unexpected NUL in input data");
	dsasl_client_session_destroy(&session);
	test_assert(session == NULL);

	dsasl_client_unref(&client);
	test_assert(client == NULL);

	test_end();
}

static void test_sasl_client_mech_select(void)
{
	struct settings_simple test_set;
	struct dsasl_client *client;
	struct dsasl_client_parameters params;
	struct dsasl_client_session *session;
	const char *error;
	int ret;

	client = dsasl_client_create(NULL);

	/* none */

	test_begin("sasl client mech select - none");
	static const char *settings_none[] = {
		"client_auth_mechanism", "",
		"client_auth_authid", "",
		"client_auth_authzid", "",
		"client_auth_password", "",
		NULL,
	};
	settings_simple_init(&test_set, settings_none);
	event_set_forced_debug(test_set.event, debug);

	ret = dsasl_client_session_create_auto(client, test_set.event, NULL,
					       &session, &error);
	test_assert(ret == 0);
	test_assert(session == NULL);

	settings_simple_deinit(&test_set);
	test_end();

	/* default */

	test_begin("sasl client mech select - default");
	static const char *settings_default[] = {
		"client_auth_mechanism", "",
		"client_auth_authid", "",
		"client_auth_authzid", "testuser",
		"client_auth_password", "frop",
		NULL,
	};
	settings_simple_init(&test_set, settings_default);
	event_set_forced_debug(test_set.event, debug);

	ret = dsasl_client_session_create_auto(client, test_set.event, NULL,
					       &session, &error);
	test_assert(ret > 0);
	i_assert(session != NULL);

	test_assert_strcmp(dsasl_client_session_get_mech_name(session),
			   "PLAIN");

	dsasl_client_session_destroy(&session);
	settings_simple_deinit(&test_set);
	test_end();

	/* default no PLAIN */

	test_begin("sasl client mech select - default no PLAIN");
	static const char *settings_default_no_plain[] = {
		"client_auth_mechanism", "",
		"client_auth_authid", "",
		"client_auth_authzid", "testuser",
		"client_auth_password", "frop",
		NULL,
	};
	settings_simple_init(&test_set, settings_default_no_plain);
	event_set_forced_debug(test_set.event, debug);

	static const char *mechs_default_no_plain[] = {
		"SCRAM-SHA-1", "LOGIN", NULL,
	};
	i_zero(&params);
	params.server_mechanisms = mechs_default_no_plain;

	ret = dsasl_client_session_create_auto(client, test_set.event, &params,
					       &session, &error);
	test_assert(ret > 0);
	i_assert(session != NULL);

	test_assert_strcmp(dsasl_client_session_get_mech_name(session),
			   "SCRAM-SHA-1");

	dsasl_client_session_destroy(&session);
	settings_simple_deinit(&test_set);
	test_end();

	/* explicit PLAIN */

	test_begin("sasl client mech select - explicit PLAIN");
	static const char *settings_explicit_plain[] = {
		"client_auth_mechanism", "PLAIN",
		"client_auth_authid", "",
		"client_auth_authzid", "testuser",
		"client_auth_password", "frop",
		NULL,
	};
	settings_simple_init(&test_set, settings_explicit_plain);
	event_set_forced_debug(test_set.event, debug);

	ret = dsasl_client_session_create_auto(client, test_set.event, NULL,
					       &session, &error);
	test_assert(ret > 0);
	i_assert(session != NULL);

	test_assert_strcmp(dsasl_client_session_get_mech_name(session),
			   "PLAIN");

	dsasl_client_session_destroy(&session);
	settings_simple_deinit(&test_set);
	test_end();

	/* explicit LOGIN */

	test_begin("sasl client mech select - explicit LOGIN");
	static const char *settings_explicit_login[] = {
		"client_auth_mechanism", "LOGIN",
		"client_auth_authid", "",
		"client_auth_authzid", "testuser",
		"client_auth_password", "frop",
		NULL,
	};
	settings_simple_init(&test_set, settings_explicit_login);
	event_set_forced_debug(test_set.event, debug);

	ret = dsasl_client_session_create_auto(client, test_set.event, NULL,
					       &session, &error);
	test_assert(ret > 0);
	i_assert(session != NULL);

	test_assert_strcmp(dsasl_client_session_get_mech_name(session),
			   "LOGIN");

	dsasl_client_session_destroy(&session);
	settings_simple_deinit(&test_set);
	test_end();

	/* configured default */

	test_begin("sasl client mech select - configured default");
	static const char *settings_configured_default[] = {
		"client_auth", "PLAIN LOGIN",
		"client_auth/PLAIN/mechanism", "PLAIN",
		"client_auth/PLAIN/authid", "",
		"client_auth/PLAIN/authzid", "testuser",
		"client_auth/PLAIN/password", "frop",
		"client_auth/LOGIN/mechanism", "LOGIN",
		"client_auth/LOGIN/authid", "",
		"client_auth/LOGIN/authzid", "testuser",
		"client_auth/LOGIN/password", "frop",
		NULL,
	};
	settings_simple_init(&test_set, settings_configured_default);
	event_set_forced_debug(test_set.event, debug);

	ret = dsasl_client_session_create_auto(client, test_set.event, NULL,
					       &session, &error);
	test_assert(ret > 0);
	i_assert(session != NULL);

	test_assert_strcmp(dsasl_client_session_get_mech_name(session),
			   "PLAIN");

	dsasl_client_session_destroy(&session);
	settings_simple_deinit(&test_set);
	test_end();

	/* configured first */

	test_begin("sasl client mech select - configured first");
	static const char *settings_configured_first[] = {
		"client_auth", "PLAIN LOGIN",
		"client_auth/PLAIN/mechanism", "PLAIN",
		"client_auth/PLAIN/authid", "",
		"client_auth/PLAIN/authzid", "testuser",
		"client_auth/PLAIN/password", "frop",
		"client_auth/LOGIN/mechanism", "LOGIN",
		"client_auth/LOGIN/authid", "",
		"client_auth/LOGIN/authzid", "testuser",
		"client_auth/LOGIN/password", "frop",
		NULL,
	};
	settings_simple_init(&test_set, settings_configured_first);
	event_set_forced_debug(test_set.event, debug);

	static const char *mechs_configured_first[] = {
		"LOGIN", "PLAIN", NULL,
	};
	i_zero(&params);
	params.server_mechanisms = mechs_configured_first;

	ret = dsasl_client_session_create_auto(client, test_set.event, &params,
					       &session, &error);
	test_assert(ret > 0);
	i_assert(session != NULL);

	test_assert_strcmp(dsasl_client_session_get_mech_name(session),
			   "PLAIN");

	dsasl_client_session_destroy(&session);
	settings_simple_deinit(&test_set);
	test_end();

	/* configured second */

	test_begin("sasl client mech select - configured second");
	static const char *settings_configured_second[] = {
		"client_auth", "PLAIN LOGIN",
		"client_auth/PLAIN/mechanism", "PLAIN",
		"client_auth/PLAIN/authid", "",
		"client_auth/PLAIN/authzid", "testuser",
		"client_auth/PLAIN/password", "frop",
		"client_auth/LOGIN/mechanism", "LOGIN",
		"client_auth/LOGIN/authid", "",
		"client_auth/LOGIN/authzid", "testuser",
		"client_auth/LOGIN/password", "frop",
		NULL,
	};
	settings_simple_init(&test_set, settings_configured_second);
	event_set_forced_debug(test_set.event, debug);

	static const char *mechs_configured_second[] = {
		"SCRAM-SHA-1", "LOGIN", NULL,
	};
	i_zero(&params);
	params.server_mechanisms = mechs_configured_second;

	ret = dsasl_client_session_create_auto(client, test_set.event, &params,
					       &session, &error);
	test_assert(ret > 0);
	i_assert(session != NULL);

	test_assert_strcmp(dsasl_client_session_get_mech_name(session),
			   "LOGIN");

	dsasl_client_session_destroy(&session);
	settings_simple_deinit(&test_set);
	test_end();

	dsasl_client_unref(&client);
}

int main(int argc ATTR_UNUSED, char *argv[])
{
	int c;
	int ret;

	lib_init();

	static void (*const test_functions[])(void) = {
		test_sasl_client_login,
		test_sasl_client_plain,
		test_sasl_client_external,
		test_sasl_client_oauthbearer,
		test_sasl_client_xoauth2,
		test_sasl_client_mech_select,
		NULL
	};

	while ((c = getopt(argc, argv, "D")) > 0) {
		switch (c) {
		case 'D':
			debug = TRUE;
			break;
		default:
			i_fatal("Usage: %s [-D]", argv[0]);
		}
	}

	ret = test_run(test_functions);

	settings_root_deinit(&set_root);
	lib_deinit();

	return ret;
}
