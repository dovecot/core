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

static void test_sasl_client_login(void)
{
	const char *error;
	test_begin("sasl client LOGIN");
	const struct dsasl_client_mech *mech = dsasl_client_mech_find("login");
	i_assert(mech != NULL);
	struct dsasl_client *client = dsasl_client_new(mech, &sasl_set);
	i_assert(client != NULL);

	string_t *input = t_str_new(64);
	string_t *output_s = t_str_new(64);
	const unsigned char *output;
	size_t olen;

	/* parameters shouldn't work (test here for completeness) */
	test_assert(dsasl_client_set_parameter(client, "parameter", "value", &error) == 0);

	/* Any input is valid */
	str_append(input, "Username:");
	test_assert(dsasl_client_input(client, input->data, input->used, &error) == 0);
	test_assert(dsasl_client_output(client, &output, &olen, &error) == 0);
	/* see what we got */
	str_append_data(output_s, output, olen);
	test_assert_strcmp(str_c(output_s), "testuser");

	str_truncate(input, 0);
	str_truncate(output_s, 0);

	str_append(input, "Password:");
	test_assert(dsasl_client_input(client, input->data, input->used, &error) == 0);
	test_assert(dsasl_client_output(client, &output, &olen, &error) == 0);
	str_append_data(output_s, output, olen);
	test_assert_strcmp(str_c(output_s), "testpassword");

	/* there should be no results to collect, we can reuse error here */
	test_assert(dsasl_client_get_result(client, "parameter", &error, &error) == 0);

	dsasl_client_free(&client);
	test_assert(client == NULL);

	/* server sends input after password */
	client = dsasl_client_new(mech, &sasl_set);
	i_assert(client != NULL);
	test_assert(dsasl_client_input(client, uchar_empty_ptr, 0, &error) == 0);
	test_assert(dsasl_client_output(client, &output, &olen, &error) == 0);
	test_assert(dsasl_client_input(client, uchar_empty_ptr, 0, &error) == 0);
	test_assert(dsasl_client_output(client, &output, &olen, &error) == 0);
	test_assert(dsasl_client_input(client, uchar_empty_ptr, 0, &error) == -1);
	test_assert_strcmp(error, "Server didn't finish authentication");

	dsasl_client_free(&client);

	/* missing username & password */
	client = dsasl_client_new(mech, &sasl_empty_set);
	i_assert(client != NULL);

	test_assert(dsasl_client_input(client, uchar_empty_ptr, 0, &error) == 0);
	test_assert(dsasl_client_output(client, &output, &olen, &error) == -1);
	test_assert_strcmp(error, "authid not set");
	dsasl_client_free(&client);

	/* missing password */
	client = dsasl_client_new(mech, &sasl_no_password_set);
	i_assert(client != NULL);

	test_assert(dsasl_client_input(client, uchar_empty_ptr, 0, &error) == 0);
	test_assert(dsasl_client_output(client, &output, &olen, &error) == -1);
	test_assert_strcmp(error, "password not set");
	dsasl_client_free(&client);

	/* unexpected NUL byte in input */
	client = dsasl_client_new(mech, &sasl_set);
	i_assert(client != NULL);

	str_truncate(input, 0);
	str_append_data(input, "unexpected\0", 11);
	test_assert(dsasl_client_input(client, input->data, input->used, &error) == -1);
	test_assert_strcmp(error, "Unexpected NUL in input data");
	dsasl_client_free(&client);

	test_end();
}

static void test_sasl_client_plain(void)
{
	const char *error;
	test_begin("sasl client PLAIN");
	const struct dsasl_client_mech *mech = dsasl_client_mech_find("plain");
	i_assert(mech != NULL);
	struct dsasl_client *client = dsasl_client_new(mech, &sasl_set);
	i_assert(client != NULL);

	const unsigned char *output;
	size_t olen;

	test_assert(dsasl_client_input(client, uchar_empty_ptr, 0, &error) == 0);
	test_assert(dsasl_client_output(client, &output, &olen, &error) == 0);
	const unsigned char expected[] = "\0testuser\0testpassword";
	/* there is no NUL byte at the end */
	test_assert(olen == sizeof(expected) - 1);
	test_assert(memcmp(output, expected, I_MIN(sizeof(expected) - 1, olen)) == 0);

	dsasl_client_free(&client);
	test_assert(client == NULL);

	client = dsasl_client_new(mech, &sasl_master_set);
	i_assert(client != NULL);

	test_assert(dsasl_client_input(client, uchar_empty_ptr, 0, &error) == 0);
	test_assert(dsasl_client_output(client, &output, &olen, &error) == 0);
	const unsigned char expected_master[] =
		"testuser\0masteruser\0masterpassword";
	/* there is no NUL byte at the end */
	test_assert(olen == sizeof(expected_master) - 1);
	test_assert(memcmp(output, expected_master,
			   I_MIN(sizeof(expected_master) - 1, olen)) == 0);

	dsasl_client_free(&client);

	/* unexpected initial response */
	const unsigned char input[] = "ir";
	client = dsasl_client_new(mech, &sasl_set);
	i_assert(client != NULL);
	test_assert(dsasl_client_input(client, input, sizeof(input)-1, &error) == -1);
	test_assert_strcmp(error, "Server sent non-empty initial response");

	dsasl_client_free(&client);

	/* server sends input after response */
	client = dsasl_client_new(mech, &sasl_set);
	i_assert(client != NULL);
	test_assert(dsasl_client_input(client, uchar_empty_ptr, 0, &error) == 0);
	test_assert(dsasl_client_output(client, &output, &olen, &error) == 0);
	test_assert(dsasl_client_input(client, uchar_empty_ptr, 0, &error) == -1);
	test_assert_strcmp(error, "Server didn't finish authentication");

	dsasl_client_free(&client);

	/* missing username & password */
	client = dsasl_client_new(mech, &sasl_empty_set);
	i_assert(client != NULL);

	test_assert(dsasl_client_input(client, uchar_empty_ptr, 0, &error) == 0);
	test_assert(dsasl_client_output(client, &output, &olen, &error) == -1);
	test_assert_strcmp(error, "authid not set");
	dsasl_client_free(&client);

	/* missing password */
	client = dsasl_client_new(mech, &sasl_no_password_set);
	i_assert(client != NULL);

	test_assert(dsasl_client_input(client, uchar_empty_ptr, 0, &error) == 0);
	test_assert(dsasl_client_output(client, &output, &olen, &error) == -1);
	test_assert_strcmp(error, "password not set");
	dsasl_client_free(&client);

	/* unexpected NUL byte in input */
	client = dsasl_client_new(mech, &sasl_set);
	i_assert(client != NULL);

	const unsigned char input2[] = "unexpected\0";
	test_assert(dsasl_client_input(client, input2, sizeof(input2), &error) == -1);
	test_assert_strcmp(error, "Unexpected NUL in input data");
	dsasl_client_free(&client);

	test_end();
}

static void test_sasl_client_external(void)
{
	const char *error;
	test_begin("sasl client EXTERNAL");
	const struct dsasl_client_mech *mech = dsasl_client_mech_find("external");
	i_assert(mech != NULL);
	struct dsasl_client *client = dsasl_client_new(mech, &sasl_set);
	i_assert(client != NULL);

	const unsigned char *output;
	size_t olen;

	test_assert(dsasl_client_input(client, uchar_empty_ptr, 0, &error) == 0);
	test_assert(dsasl_client_output(client, &output, &olen, &error) == 0);
	const unsigned char expected[] = "testuser";
	/* there is no NUL byte at the end */
	test_assert(olen == sizeof(expected) - 1);
	test_assert(memcmp(output, expected, I_MIN(sizeof(expected) - 1, olen)) == 0);

	dsasl_client_free(&client);
	test_assert(client == NULL);

	client = dsasl_client_new(mech, &sasl_master_set);
	i_assert(client != NULL);

	test_assert(dsasl_client_input(client, uchar_empty_ptr, 0, &error) == 0);
	test_assert(dsasl_client_output(client, &output, &olen, &error) == 0);
	const unsigned char expected_master[] =	"testuser";
	/* there is no NUL byte at the end */
	test_assert(olen == sizeof(expected_master) - 1);
	test_assert(memcmp(output, expected_master,
			   I_MIN(sizeof(expected_master) - 1, olen)) == 0);

	dsasl_client_free(&client);

	/* unexpected NUL byte in input */
	client = dsasl_client_new(mech, &sasl_set);
	i_assert(client != NULL);

	const unsigned char input2[] = "unexpected\0";
	test_assert(dsasl_client_input(client, input2, sizeof(input2), &error) == -1);
	test_assert_strcmp(error, "Unexpected NUL in input data");
	dsasl_client_free(&client);

	test_end();
}

static void test_sasl_client_oauthbearer(void)
{
	const char *error;
	const char *value;
	test_begin("sasl client OAUTHBEARER");
	const struct dsasl_client_mech *mech = dsasl_client_mech_find("oauthbearer");
	i_assert(mech != NULL);
	struct dsasl_client *client = dsasl_client_new(mech, &sasl_set);
	i_assert(client != NULL);

	string_t *input = t_str_new(64);
	const unsigned char *output;
	size_t olen;

	test_assert(dsasl_client_input(client, uchar_empty_ptr, 0, &error) == 0);
	test_assert(dsasl_client_output(client, &output, &olen, &error) == 0);
	test_assert(dsasl_client_input(client, uchar_empty_ptr, 0, &error) == 0);

	const unsigned char expected[] = "n,a=testuser,\1"
		"auth=Bearer testpassword\1\1";
	/* there is no NUL byte at the end */
	test_assert(olen == sizeof(expected) - 1);
	test_assert(memcmp(output, expected, I_MIN(sizeof(expected) - 1, olen)) == 0);
	test_assert(dsasl_client_get_result(client, "status", &value, &error) == 1);
	test_assert_strcmp(value, "");

	dsasl_client_free(&client);
	test_assert(client == NULL);

	/* with host & port set */
	client = dsasl_client_new(mech, &sasl_set);
	i_assert(client != NULL);

	test_assert(dsasl_client_set_parameter(client, "host", "example.com", &error) == 1);
	test_assert(dsasl_client_set_parameter(client, "port", "imap", &error) == -1);
	test_assert_strcmp(error, "Invalid port value");
	test_assert(dsasl_client_set_parameter(client, "port", "143", &error) == 1);
	test_assert(dsasl_client_set_parameter(client, "unknown", "value", &error) == 0);

	test_assert(dsasl_client_input(client, uchar_empty_ptr, 0, &error) == 0);
	test_assert(dsasl_client_output(client, &output, &olen, &error) == 0);
	test_assert(dsasl_client_input(client, uchar_empty_ptr, 0, &error) == 0);

	const unsigned char expected_h_p[] = "n,a=testuser,\1"
		"host=example.com\1"
		"port=143\1"
		"auth=Bearer testpassword\1\1";
	/* there is no NUL byte at the end */
	test_assert(olen == sizeof(expected_h_p) - 1);
	test_assert(memcmp(output, expected_h_p,
			   I_MIN(sizeof(expected_h_p) - 1, olen)) == 0);

	dsasl_client_free(&client);
	test_assert(client == NULL);

	client = dsasl_client_new(mech, &sasl_set);
	/* test error response */
	test_assert(dsasl_client_input(client, uchar_empty_ptr, 0, &error) == 0);
	test_assert(dsasl_client_output(client, &output, &olen, &error) == 0);
	test_assert(dsasl_client_input(client, uchar_empty_ptr, 0, &error) == 0);
	str_append(input, "{\"status\":\"401\",\"schemes\":\"bearer\",\"scope\":\"mail\"}");
	test_assert(dsasl_client_input(client, input->data, input->used, &error) == -1);
	test_assert_strcmp(error, "Failed to authenticate: 401");
	test_assert(dsasl_client_get_result(client, "status", &value, &error) == 1);
	test_assert_strcmp(value, "401");

	dsasl_client_free(&client);

	/* missing username & password */
	client = dsasl_client_new(mech, &sasl_empty_set);
	i_assert(client != NULL);

	test_assert(dsasl_client_input(client, uchar_empty_ptr, 0, &error) == 0);
	test_assert(dsasl_client_output(client, &output, &olen, &error) == -1);
	test_assert_strcmp(error, "authid not set");
	dsasl_client_free(&client);

	/* missing password */
	client = dsasl_client_new(mech, &sasl_no_password_set);
	i_assert(client != NULL);

	test_assert(dsasl_client_input(client, uchar_empty_ptr, 0, &error) == 0);
	test_assert(dsasl_client_output(client, &output, &olen, &error) == -1);
	test_assert_strcmp(error, "password not set");
	dsasl_client_free(&client);

	/* unexpected NUL byte in input */
	client = dsasl_client_new(mech, &sasl_set);
	i_assert(client != NULL);

	const unsigned char input2[] = "unexpected\0";
	test_assert(dsasl_client_input(client, input2, sizeof(input2), &error) == -1);
	test_assert_strcmp(error, "Unexpected NUL in input data");
	dsasl_client_free(&client);

	test_end();
}

static void test_sasl_client_xoauth2(void)
{
	const char *error;
	test_begin("sasl client XOAUTH2");
	const struct dsasl_client_mech *mech = dsasl_client_mech_find("xoauth2");
	i_assert(mech != NULL);
	struct dsasl_client *client = dsasl_client_new(mech, &sasl_set);
	i_assert(client != NULL);

	string_t *input = t_str_new(64);
	const unsigned char *output;
	size_t olen;

	test_assert(dsasl_client_input(client, uchar_empty_ptr, 0, &error) == 0);
	test_assert(dsasl_client_output(client, &output, &olen, &error) == 0);
	test_assert(dsasl_client_input(client, uchar_empty_ptr, 0, &error) == 0);

	const unsigned char expected[] = "user=testuser\1auth=Bearer testpassword\1\1";
	/* there is no NUL byte at the end */
	test_assert(olen == sizeof(expected) - 1);
	test_assert(memcmp(output, expected, I_MIN(sizeof(expected) - 1, olen)) == 0);

	dsasl_client_free(&client);
	test_assert(client == NULL);

	client = dsasl_client_new(mech, &sasl_set);
	/* test error response */
	test_assert(dsasl_client_input(client, uchar_empty_ptr, 0, &error) == 0);
	test_assert(dsasl_client_output(client, &output, &olen, &error) == 0);
	test_assert(dsasl_client_input(client, uchar_empty_ptr, 0, &error) == 0);
	str_append(input, "{\"status\":\"401\",\"schemes\":\"bearer\",\"scope\":\"mail\"}");
	test_assert(dsasl_client_input(client, input->data, input->used, &error) == -1);
	test_assert_strcmp(error, "Failed to authenticate: 401");

	dsasl_client_free(&client);

	/* missing username & password */
	client = dsasl_client_new(mech, &sasl_empty_set);
	i_assert(client != NULL);

	test_assert(dsasl_client_input(client, uchar_empty_ptr, 0, &error) == 0);
	test_assert(dsasl_client_output(client, &output, &olen, &error) == -1);
	test_assert_strcmp(error, "authid not set");
	dsasl_client_free(&client);

	/* missing password */
	client = dsasl_client_new(mech, &sasl_no_password_set);
	i_assert(client != NULL);

	test_assert(dsasl_client_input(client, uchar_empty_ptr, 0, &error) == 0);
	test_assert(dsasl_client_output(client, &output, &olen, &error) == -1);
	test_assert_strcmp(error, "password not set");
	dsasl_client_free(&client);

	/* unexpected NUL byte in input */
	client = dsasl_client_new(mech, &sasl_set);
	i_assert(client != NULL);

	const unsigned char input2[] = "unexpected\0";
	test_assert(dsasl_client_input(client, input2, sizeof(input2), &error) == -1);
	test_assert_strcmp(error, "Unexpected NUL in input data");
	dsasl_client_free(&client);

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
	dsasl_clients_init();
	int ret = test_run(test_functions);
	dsasl_clients_deinit();
	return ret;
}
