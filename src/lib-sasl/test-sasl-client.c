/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "str.h"
#include "strfuncs.h"
#include "test-common.h"
#include "dsasl-client.h"

static const struct dsasl_client_settings sasl_empty_set = {
	.authid = NULL,
};

static const struct dsasl_client_settings sasl_no_password_set = {
	.authid = "testuser",
};

static const struct dsasl_client_settings sasl_set = {
	.authid = "testuser",
	.password = "testpassword"
};

static const struct dsasl_client_settings sasl_master_set = {
	.authzid = "testuser",
	.authid = "masteruser",
	.password = "masterpassword"
};

static struct dsasl_client_session *
test_init_sasl_session_params(struct dsasl_client *client,
			      const struct dsasl_client_mech *mech,
			      const struct dsasl_client_parameters *params,
			      const struct dsasl_client_settings *set,
			      const char **error_r)
{
	struct dsasl_client_session *session;

	if (dsasl_client_session_create(client, NULL, mech, params, set,
					&session, error_r) < 0)
		session = NULL;

	return session;
}

static struct dsasl_client_session *
test_init_sasl_session(struct dsasl_client *client,
		       const struct dsasl_client_mech *mech,
		       const struct dsasl_client_settings *set,
		       const char **error_r)
{
	struct dsasl_client_parameters params = {
	};

	return test_init_sasl_session_params(client, mech, &params, set,
					     error_r);
}

static void test_sasl_client_login(void)
{
	struct dsasl_client *client;
	const struct dsasl_client_mech *mech;
	struct dsasl_client_session *session;
	const char *error;

	test_begin("sasl client LOGIN");

	client = dsasl_client_create(NULL);
	mech = dsasl_client_mech_find(client, "login");
	i_assert(mech != NULL);

	string_t *input = t_str_new(64);
	string_t *output_s = t_str_new(64);
	const unsigned char *output;
	size_t olen;

	session = test_init_sasl_session(client, mech, &sasl_set, &error);
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
	session = test_init_sasl_session(client, mech, &sasl_set, &error);
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
	session = test_init_sasl_session(client, mech, &sasl_empty_set, &error);
	i_assert(session == NULL);
	test_assert(str_begins_with(error, "No authentication or authorization identity configured for the LOGIN mechanism"));

	/* missing password */
	session = test_init_sasl_session(client, mech, &sasl_no_password_set, &error);
	i_assert(session == NULL);
	test_assert_strcmp(error, "No password configured (client_auth_password setting)");

	/* unexpected NUL byte in input */
	session = test_init_sasl_session(client, mech, &sasl_set, &error);
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
	struct dsasl_client *client;
	const struct dsasl_client_mech *mech;
	struct dsasl_client_session *session;
	const char *error;

	test_begin("sasl client PLAIN");

	client = dsasl_client_create(NULL);
	mech = dsasl_client_mech_find(client, "plain");
	i_assert(mech != NULL);

	const unsigned char *output;
	size_t olen;

	session = test_init_sasl_session(client, mech, &sasl_set, &error);
	i_assert(session != NULL);
	test_assert(dsasl_client_session_input(session, uchar_empty_ptr, 0, &error) == DSASL_CLIENT_RESULT_OK);
	test_assert(dsasl_client_session_output(session, &output, &olen, &error) == DSASL_CLIENT_RESULT_OK);
	const unsigned char expected[] = "\0testuser\0testpassword";
	/* there is no NUL byte at the end */
	test_assert(olen == sizeof(expected) - 1);
	test_assert(memcmp(output, expected, I_MIN(sizeof(expected) - 1, olen)) == 0);
	dsasl_client_session_destroy(&session);
	test_assert(session == NULL);

	session = test_init_sasl_session(client, mech, &sasl_master_set, &error);
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
	session = test_init_sasl_session(client, mech, &sasl_set, &error);
	i_assert(session != NULL);
	test_assert(dsasl_client_session_input(session, input, sizeof(input)-1, &error) == DSASL_CLIENT_RESULT_ERR_PROTOCOL);
	test_assert_strcmp(error, "Server sent non-empty initial response");
	dsasl_client_session_destroy(&session);
	test_assert(session == NULL);

	/* server sends input after response */
	session = test_init_sasl_session(client, mech, &sasl_set, &error);
	i_assert(session != NULL);
	test_assert(dsasl_client_session_input(session, uchar_empty_ptr, 0, &error) == DSASL_CLIENT_RESULT_OK);
	test_assert(dsasl_client_session_output(session, &output, &olen, &error) == DSASL_CLIENT_RESULT_OK);
	test_assert(dsasl_client_session_input(session, uchar_empty_ptr, 0, &error) == DSASL_CLIENT_RESULT_ERR_PROTOCOL);
	test_assert_strcmp(error, "Server didn't finish authentication");
	dsasl_client_session_destroy(&session);
	test_assert(session == NULL);

	/* missing username & password */
	session = test_init_sasl_session(client, mech, &sasl_empty_set, &error);
	i_assert(session == NULL);
	test_assert(str_begins_with(error, "No authentication or authorization identity configured for the PLAIN mechanism"));

	/* missing password */
	session = test_init_sasl_session(client, mech, &sasl_no_password_set, &error);
	i_assert(session == NULL);
	test_assert_strcmp(error, "No password configured (client_auth_password setting)");

	/* unexpected NUL byte in input */
	session = test_init_sasl_session(client, mech, &sasl_set, &error);
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
	struct dsasl_client *client;
	const struct dsasl_client_mech *mech;
	struct dsasl_client_session *session;
	const char *error;

	test_begin("sasl client EXTERNAL");

	client = dsasl_client_create(NULL);
	mech = dsasl_client_mech_find(client, "external");
	i_assert(mech != NULL);

	const unsigned char *output;
	size_t olen;

	session = test_init_sasl_session(client, mech, &sasl_set, &error);
	i_assert(session != NULL);
	test_assert(dsasl_client_session_input(session, uchar_empty_ptr, 0, &error) == DSASL_CLIENT_RESULT_OK);
	test_assert(dsasl_client_session_output(session, &output, &olen, &error) == DSASL_CLIENT_RESULT_OK);
	const unsigned char expected[] = "testuser";
	/* there is no NUL byte at the end */
	test_assert(olen == sizeof(expected) - 1);
	test_assert(memcmp(output, expected, I_MIN(sizeof(expected) - 1, olen)) == 0);
	dsasl_client_session_destroy(&session);
	test_assert(session == NULL);

	session = test_init_sasl_session(client, mech, &sasl_master_set, &error);
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
	session = test_init_sasl_session(client, mech, &sasl_set, &error);
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
	struct dsasl_client *client;
	const struct dsasl_client_mech *mech;
	struct dsasl_client_session *session;
	const char *error;
	const char *value;

	test_begin("sasl client OAUTHBEARER");

	client = dsasl_client_create(NULL);
	mech = dsasl_client_mech_find(client, "oauthbearer");
	i_assert(mech != NULL);

	string_t *input = t_str_new(64);
	const unsigned char *output;
	size_t olen;

	session = test_init_sasl_session(client, mech, &sasl_set, &error);
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
	session = test_init_sasl_session_params(client, mech, &params, &sasl_set, &error);
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
	session = test_init_sasl_session(client, mech, &sasl_set, &error);
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
	session = test_init_sasl_session(client, mech, &sasl_empty_set, &error);
	i_assert(session == NULL);
	test_assert(str_begins_with(error, "No authentication or authorization identity configured for the OAUTHBEARER mechanism"));

	/* missing password */
	session = test_init_sasl_session(client, mech, &sasl_no_password_set, &error);
	i_assert(session == NULL);
	test_assert_strcmp(error, "No password configured (client_auth_password setting)");

	/* unexpected NUL byte in input */
	session = test_init_sasl_session(client, mech, &sasl_set, &error);
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
	struct dsasl_client *client;
	const struct dsasl_client_mech *mech;
	struct dsasl_client_session *session;
	const char *error;

	test_begin("sasl client XOAUTH2");

	client = dsasl_client_create(NULL);
	mech = dsasl_client_mech_find(client, "xoauth2");
	i_assert(mech != NULL);

	string_t *input = t_str_new(64);
	const unsigned char *output;
	size_t olen;

	session = test_init_sasl_session(client, mech, &sasl_set, &error);
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
	session = test_init_sasl_session(client, mech, &sasl_set, &error);
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
	session = test_init_sasl_session(client, mech, &sasl_empty_set, &error);
	i_assert(session == NULL);
	test_assert(str_begins_with(error, "No authentication or authorization identity configured for the XOAUTH2 mechanism"));

	/* missing password */
	session = test_init_sasl_session(client, mech, &sasl_no_password_set, &error);
	i_assert(session == NULL);
	test_assert_strcmp(error, "No password configured (client_auth_password setting)");

	/* unexpected NUL byte in input */
	session = test_init_sasl_session(client, mech, &sasl_set, &error);
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

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_sasl_client_login,
		test_sasl_client_plain,
		test_sasl_client_external,
		test_sasl_client_oauthbearer,
		test_sasl_client_xoauth2,
		NULL
	};
	int ret = test_run(test_functions);
	return ret;
}
