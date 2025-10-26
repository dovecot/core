/* Copyright (c) 2020 Dovecot authors, see the included COPYING file */

#include "test-auth.h"
#include "auth.h"
#include "str.h"
#include "ioloop.h"
#include "master-service.h"
#include "auth-common.h"
#include "auth-sasl.h"
#include "auth-request.h"
#include "auth-request-handler-private.h"
#include "auth-settings.h"
#include "auth-token.h"

#include <unistd.h>
#include <time.h>

#define UCHAR_LEN(str) (const unsigned char *)(str), sizeof(str)-1

struct test_case {
	const char *mech_name;
	const unsigned char *in;
	size_t len;
	const char *username;
	const char *expect_error;
	bool success;
	bool set_username_before_test;
	bool set_cert_username;
};

static void
verify_plain_continue_mock_callback(struct auth_request *request,
				    verify_plain_callback_t *callback)
{
	request->passdb_success = TRUE;
	callback(PASSDB_RESULT_OK, request);
	io_loop_stop(current_ioloop);
}

static void
request_handler_reply_mock_callback(struct auth_request *request,
				    enum auth_client_result result,
				    const void *auth_reply ATTR_UNUSED,
				    size_t reply_size ATTR_UNUSED)
{
	request->failed = result != AUTH_CLIENT_RESULT_SUCCESS;

	if (request->passdb_result == PASSDB_RESULT_OK)
		request->failed = FALSE;
	else if (strcmp(request->fields.mech_name, SASL_MECH_NAME_OTP) == 0) {
		if (null_strcmp(request->fields.user, "otp_phase_2") == 0)
			request->failed = FALSE;
	} else if (strcmp(request->fields.mech_name,
			  SASL_MECH_NAME_OAUTHBEARER) == 0) {
	}
};

static void
request_handler_reply_continue_mock_callback(struct auth_request *request,
					     const void *reply,
					     size_t reply_size)
{
	request->context = p_strndup(request->pool, reply, reply_size);
}

static void
auth_client_request_mock_callback(
	const char *reply ATTR_UNUSED,
	struct auth_client_connection *conn ATTR_UNUSED)
{
}

static void test_mech_prepare_request(struct auth_request **request_r,
				      const char *mech_name,
				      struct auth_request_handler *handler,
				      unsigned int running_test,
				      const struct test_case *test_case)
{
	struct auth_request *request = auth_request_new(NULL);
	struct auth_settings *new_set =
		p_memdup(request->pool, global_auth_settings,
			 sizeof(*global_auth_settings));
	new_set->ssl_username_from_cert = test_case->set_cert_username;

	request->handler = handler;
	request->id = running_test+1;
	request->mech_password = NULL;
	request->fields.protocol = "service";
	request->state = AUTH_REQUEST_STATE_NEW;
	request->set = new_set;
	request->protocol_set = global_auth_settings;
	request->connect_uid = running_test;
	handler->refcount = 1;

	struct auth *auth = auth_default_protocol();
	const struct sasl_server_mech *mech;
	if (strcmp(mech_name, AUTH_SASL_MECH_NAME_DOVECOT_TOKEN) == 0)
		mech = auth->sasl_mech_dovecot_token;
	else
		mech = sasl_server_mech_find(auth->sasl_inst, mech_name);
	i_assert(mech != NULL);

	auth_request_init_sasl(request, mech);

	request->failure_nodelay = TRUE;
	auth_request_state_count[AUTH_REQUEST_STATE_NEW] = 1;

	if (test_case->set_username_before_test ||
	    test_case->set_cert_username) {
		request->fields.user =
			p_strdup(request->pool, test_case->username);
	}
	if (test_case->set_username_before_test) {
		sasl_server_request_test_set_authid(&request->sasl.req,
						    test_case->username);
	}
	if (test_case->set_cert_username)
		request->fields.cert_username = TRUE;

	*request_r = request;
}

static void
test_mech_handle_challenge(struct auth_request *request,
			   const unsigned char *in, size_t in_len,
			   unsigned int running_test, bool expected_success)
{
	string_t *out = t_str_new(16);
	str_append_data(out, in, in_len);
	const char *challenge = request->context;

	if (strcmp(request->fields.mech_name, SASL_MECH_NAME_LOGIN) == 0) {
		/* We do not care about any specific password just give the
		   username input as password also in case it's wanted. */
		if (expected_success) {
			test_assert_strcmp_idx(challenge, "Password:",
					       running_test);
		} else {
			test_assert_strcmp_idx(challenge, "Username:",
					       running_test);
		}
	} else if (strcmp(request->fields.mech_name,
			  SASL_MECH_NAME_CRAM_MD5) == 0 &&
		   *in != '\0') {
		str_truncate(out, 0);
		str_append(out, "testuser b913a602c7eda7a495b4e6e7334d3890");
	} else if (strcmp(request->fields.mech_name,
			  SASL_MECH_NAME_DIGEST_MD5) == 0) {
		sasl_server_mech_digest_md5_test_set_nonce(
			&request->sasl.req, "OA6MG9tEQGm2hh");
	}
	auth_request_continue(request, out->data, out->used);
}

static inline const unsigned char *
test_mech_construct_apop_challenge(unsigned int connect_uid, size_t *len_r)
{
	string_t *apop_challenge = t_str_new(128);

	str_printfa(apop_challenge,"<%lx.%lx.%"PRIxTIME_T".", (unsigned long)getpid(),
		    (unsigned long)connect_uid, process_start_time+10);
	str_append_data(apop_challenge, "\0testuser\0responseoflen16-", 26);
	*len_r = apop_challenge->used;
	return apop_challenge->data;
}

static void test_mechs(void)
{
	static struct auth_request_handler handler = {
		.callback = auth_client_request_mock_callback,
		.reply_callback = request_handler_reply_mock_callback,
		.reply_continue_callback =
			request_handler_reply_continue_mock_callback,
		.verify_plain_continue_callback =
			verify_plain_continue_mock_callback,
	};

	static struct test_case tests[] = {
		/* Expected to be successful */
		{"ANONYMOUS", UCHAR_LEN("\0any \0 bad \0 content"), "anonuser", NULL, TRUE, FALSE, FALSE},
		{"APOP", NULL, 0, "testuser", NULL, TRUE, FALSE, FALSE},
		{"CRAM-MD5", UCHAR_LEN("testuser b913a602c7eda7a495b4e6e7334d3890"), "testuser", NULL, TRUE, FALSE, FALSE},
		{"DIGEST-MD5", UCHAR_LEN("username=\"testuser@example.com\",realm=\"example.com\",nonce=\"OA6MG9tEQGm2hh\",cnonce=\"OA6MHXh6VqTrRk\",nc=00000001,digest-uriresponse=d388dad90d4bbd760a152321f2143af7,qop=\"auth\""), "testuser@example.com", NULL,TRUE, FALSE, FALSE},
		{"DIGEST-MD5", UCHAR_LEN("username=\"testuser@example.com\",realm=\"example.com\",nonce=\"OA6MG9tEQGm2hh\",cnonce=\"OA6MHXh6VqTrRk\",nc=00000001,digest-uriresponse=d388dad90d4bbd760a152321f2143af7,qop=\"auth\",authzid=\"masteruser\""), "testuser@example.com", NULL, TRUE, FALSE, FALSE},
		{"DIGEST-MD5", UCHAR_LEN("username=\"test\xc3\xbaser@example.com\",realm=\"example.com\",nonce=\"OA6MG9tEQGm2hh\",cnonce=\"OA6MHXh6VqTrRk\",nc=00000001,digest-uriresponse=d388dad90d4bbd760a152321f2143af7,qop=\"auth\",authzid=\"masteruser\""), "test\xc3\xbaser@example.com", NULL, TRUE, FALSE, FALSE},
		{"DIGEST-MD5", UCHAR_LEN("username=\"test\xc3\xbaser@example.com\",realm=\"example.com\",nonce=\"OA6MG9tEQGm2hh\",cnonce=\"OA6MHXh6VqTrRk\",charset=\"utf-8\",cipher=unsupported,nc=00000001,digest-uri=imap/server.com,response=d388dad90d4bbd760a152321f2143af7,qop=\"auth\",authzid=\"masteruser\""), "test\xc3\xbaser@example.com", NULL, TRUE, FALSE, FALSE},
		{"DIGEST-MD5", UCHAR_LEN("username=\"testuser\",realm=\"example.com\",nonce=\"OA6MG9tEQGm2hh\",cnonce=\"OA6MHXh6VqTrRk\",charset=\"utf-8\",cipher=unsupported,nc=00000001,digest-uri=imap/server.com,response=d388dad90d4bbd760a152321f2143af7,qop=\"auth\",authzid=\"masteruser\""), "testuser@example.com", NULL, TRUE, FALSE, FALSE},
		{"EXTERNAL", UCHAR_LEN(""), "testuser", NULL, TRUE, FALSE, TRUE},
		{"DOVECOT-TOKEN", NULL, 0, "testuser", NULL, TRUE, FALSE, FALSE},
		{"LOGIN", UCHAR_LEN("testuser"), "testuser", NULL, TRUE, FALSE, FALSE},
		{"PLAIN", UCHAR_LEN("\0testuser\0testpass"), "testuser", NULL, TRUE, FALSE, FALSE},
		{"PLAIN", UCHAR_LEN("normaluser\0masteruser\0masterpass"), "masteruser", NULL, TRUE, FALSE, FALSE},
		{"PLAIN", UCHAR_LEN("normaluser\0normaluser\0masterpass"), "normaluser", NULL, TRUE, FALSE, FALSE},
		{"OTP", UCHAR_LEN("hex:5Bf0 75d9 959d 036f"), "otp_phase_2", NULL, TRUE, TRUE, FALSE},
		{"OTP", UCHAR_LEN("word:BOND FOGY DRAB NE RISE MART"), "otp_phase_2", NULL, TRUE, TRUE, FALSE},
		{"OTP", UCHAR_LEN("init-hex:f6bd 6b33 89b8 7203:md5 499 ke6118:23d1 b253 5ae0 2b7e"), "otp_phase_2", NULL, TRUE, TRUE, FALSE},
		{"OTP", UCHAR_LEN("init-word:END KERN BALM NICK EROS WAVY:md5 499 ke1235:BABY FAIN OILY NIL TIDY DADE"), "otp_phase_2", NULL , TRUE, TRUE, FALSE},
		{"OAUTHBEARER", UCHAR_LEN("n,a=testuser,p=cHJvb2Y=,f=nonstandart\x01host=server\x01port=143\x01""auth=Bearer vF9dft4qmTc2Nvb3RlckBhbHRhdmlzdGEuY29tCg==\x01\x01"), "testuser", NULL, FALSE, TRUE, FALSE},
		{"SCRAM-SHA-1", UCHAR_LEN("n,,n=testuser,r=rOprNGfwEbeRWgbNEkqO"), "testuser", NULL, TRUE, FALSE, FALSE},
		{"SCRAM-SHA-256", UCHAR_LEN("n,,n=testuser,r=rOprNGfwEbeRWgbNEkqO"), "testuser",  NULL, TRUE, FALSE, FALSE},
		{"XOAUTH2", UCHAR_LEN("user=testuser\x01""auth=Bearer vF9dft4qmTc2Nvb3RlckBhdHRhdmlzdGEuY29tCg==\x01\x01"), "testuser", NULL, TRUE, FALSE, FALSE},

		/* Below tests are expected to fail */
		/* Empty input tests*/
		{"APOP", UCHAR_LEN(""), NULL, NULL, FALSE, FALSE, FALSE},
		{"CRAM-MD5", UCHAR_LEN(""), NULL, NULL, FALSE, FALSE, FALSE},
		{"DIGEST-MD5", UCHAR_LEN(""), NULL, NULL, FALSE, FALSE, FALSE},
		{"DOVECOT-TOKEN", UCHAR_LEN(""), NULL, NULL, FALSE, FALSE, FALSE},
		{"EXTERNAL", UCHAR_LEN(""), "testuser", NULL, FALSE, TRUE, FALSE},
		{"EXTERNAL", UCHAR_LEN(""), NULL, NULL, FALSE, FALSE, FALSE},
		{"LOGIN", UCHAR_LEN(""), NULL, NULL, FALSE, FALSE, FALSE},
		{"OTP", UCHAR_LEN(""), NULL, NULL, FALSE, FALSE, FALSE},
		{"OTP", UCHAR_LEN(""), "testuser", NULL, FALSE, FALSE, FALSE},
		{"PLAIN", UCHAR_LEN(""), NULL, NULL, FALSE, FALSE, FALSE},
		{"OAUTHBEARER", UCHAR_LEN(""), NULL, NULL, FALSE, FALSE, FALSE},
		{"XOAUTH2", UCHAR_LEN(""), NULL, NULL, FALSE, FALSE, FALSE},
		{"SCRAM-SHA-1", UCHAR_LEN(""), NULL, NULL, FALSE, FALSE, FALSE},
		{"SCRAM-SHA-256", UCHAR_LEN(""), NULL, NULL, FALSE, FALSE, FALSE},

		/* Bad input tests*/
		{"APOP", UCHAR_LEN("1.1.1\0test\0user\0response"), NULL, NULL, FALSE, FALSE, FALSE},
		{"APOP", UCHAR_LEN("1.1.1\0testuser\0tooshort"), NULL, NULL, FALSE, FALSE, FALSE},
		{"APOP", UCHAR_LEN("1.1.1\0testuser\0responseoflen16-"), NULL, NULL, FALSE, FALSE, FALSE},
		{"APOP", UCHAR_LEN("1.1.1"), NULL, NULL, FALSE, FALSE, FALSE},
		{"OTP", UCHAR_LEN("somebody\0testuser"), "testuser", NULL, FALSE, TRUE, FALSE},
		{"CRAM-MD5", UCHAR_LEN("testuser\0response"), "testuser", NULL, FALSE, FALSE, FALSE},
		{"PLAIN", UCHAR_LEN("testuser\0"), "testuser", NULL, FALSE, FALSE, FALSE},

		/* Covering most of the digest md5 parsing */
		{"DIGEST-MD5", UCHAR_LEN("username=\"testuser@example.com\",realm=\"example.com\",cnonce=\"OA6MHXh6VqTrRk\",response=d388dad90d4bbd760a152321f2143af7,qop=\"auth\""), NULL, NULL, FALSE, FALSE, FALSE},
		{"DIGEST-MD5", UCHAR_LEN("realm=\"example.com\",cnonce=\"OA6MHXh6VqTrRk\",nonce=\"OA6MG9tEQGm2hh\""), NULL, NULL, FALSE, FALSE, FALSE},
		{"DIGEST-MD5", UCHAR_LEN("username=\"testuser@example.com\",realm=\"example.com\", nonce=\"OA6MG9tEQGm2hh\""), NULL, NULL, FALSE, FALSE, FALSE},
		{"DIGEST-MD5", UCHAR_LEN("qop=\"auth-int\""), NULL, NULL, FALSE, FALSE, FALSE},
		{"DIGEST-MD5", UCHAR_LEN("qop=\"auth-int\""), NULL, NULL, FALSE, FALSE, FALSE},
		{"DIGEST-MD5", UCHAR_LEN("qop=\"auth-conf\",\"cipher=rc4\""), NULL, NULL, FALSE, FALSE, FALSE},
		{"DIGEST-MD5", UCHAR_LEN("cnonce=\"OA6MHXh6VqTrRk\",cnonce=\"OA6MHXh6VqTrRk\""), NULL, NULL, FALSE, FALSE, FALSE},
		{"DIGEST-MD5", UCHAR_LEN("cnonce=\"\""), NULL, NULL, FALSE, FALSE, FALSE},
		{"DIGEST-MD5", UCHAR_LEN("nonce=\"not matching\""), NULL, NULL, FALSE, FALSE, FALSE},
		{"DIGEST-MD5", UCHAR_LEN("nc=00000001,nc=00000002"), NULL, NULL, FALSE, FALSE, FALSE},
		{"DIGEST-MD5", UCHAR_LEN("nc=NAN"), NULL, NULL, FALSE, FALSE, FALSE},
		{"DIGEST-MD5", UCHAR_LEN("nc=00000002"), NULL, NULL, FALSE, FALSE, FALSE},
		{"DIGEST-MD5", UCHAR_LEN("cipher=unsupported"), NULL, NULL, FALSE, FALSE, FALSE},
		{"DIGEST-MD5", UCHAR_LEN("digest-uri="), NULL, NULL, FALSE, FALSE, FALSE},
		{"DIGEST-MD5", UCHAR_LEN("username=\"\""), NULL, NULL, FALSE, FALSE, FALSE},
		{"DIGEST-MD5", UCHAR_LEN("username=\"a\",username=\"b\""), NULL, NULL, FALSE, FALSE, FALSE},
		{"DIGEST-MD5", UCHAR_LEN("response=broken"), NULL, NULL, FALSE, FALSE, FALSE},
		{"DIGEST-MD5", UCHAR_LEN("maxbuf=32,maxbuf=1024"), NULL, NULL, FALSE, FALSE, FALSE},
		{"DIGEST-MD5", UCHAR_LEN("maxbuf=broken"), NULL, NULL, FALSE, FALSE, FALSE},
		{"DIGEST-MD5", UCHAR_LEN("authzid=\"somebody\",authzid=\"else\""), NULL, NULL, FALSE, FALSE, FALSE},
		{"DIGEST-MD5", UCHAR_LEN("authzid=\"\""), NULL, NULL, FALSE, FALSE, FALSE},
		{"DIGEST-MD5", UCHAR_LEN("charset=unsupported"), NULL, NULL, FALSE, FALSE, FALSE},
		{"DIGEST-MD5", UCHAR_LEN("qop=unsupported"), NULL, NULL, FALSE, FALSE, FALSE},

		/* Too much nuls */
		{"DOVECOT-TOKEN", UCHAR_LEN("service\0pid\0fail\0se\0ssion_id\0deadbeef"), NULL , NULL, FALSE, FALSE, FALSE},
		{"LOGIN", UCHAR_LEN("test user\0user"), NULL, NULL, FALSE, FALSE, FALSE},
		{"OAUTHBEARER", UCHAR_LEN("n,a==testuser,\x01""auth=Bearer token\x01\x01"), NULL, NULL, FALSE, FALSE, FALSE},
		{"OAUTHBEARER", UCHAR_LEN("F,n,a=testuser,f=non-standard\x01""auth=Bearer token\x01\x01"), "testuser", NULL, FALSE, FALSE, FALSE},
		{"OAUTHBEARER", UCHAR_LEN("n,a=testuser,f=non-standard\x01""auth=Bearer token\x01\x01"), "testuser", NULL, FALSE, TRUE, FALSE},
		{"OAUTHBEARER", UCHAR_LEN("n,a=testuser\x01""auth=token\x01\x01"), "testuser", NULL, FALSE, FALSE, FALSE},
		{"XOAUTH2", UCHAR_LEN("testuser\x01auth=Bearer token\x01\x01"), NULL, NULL, FALSE, FALSE, FALSE},
		/* does not start with [B|b]earer */
		{"XOAUTH2", UCHAR_LEN("user=testuser\x01""auth=token\x01\x01"), "testuser", NULL, FALSE, FALSE, FALSE},
		/* Too much nuls */
		{"PLAIN", UCHAR_LEN("\0fa\0il\0ing\0withthis"), NULL, NULL, FALSE, FALSE, FALSE},
		{"PLAIN", UCHAR_LEN("failingwiththis"), NULL, NULL, FALSE, FALSE, FALSE},
		{"PLAIN", UCHAR_LEN("failing\0withthis"), NULL, NULL, FALSE, FALSE, FALSE},
		{"OTP", UCHAR_LEN("someb\0ody\0testuser"), NULL, NULL, FALSE, FALSE, FALSE},
		/* phase 2 */
		{"OTP", UCHAR_LEN("someb\0ody\0testuser"), "testuser", NULL, FALSE, TRUE, FALSE},
		{"SCRAM-SHA-1", UCHAR_LEN("c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts="), NULL, NULL, FALSE, FALSE, FALSE},
		{"SCRAM-SHA-1", UCHAR_LEN("iws0X8v3Bz2T0CJGbJQyF0X+HI4Ts=,,,,"), NULL, NULL, FALSE, FALSE, FALSE},
		{"SCRAM-SHA-1", UCHAR_LEN("n,a=masteruser,,"), NULL, NULL, FALSE, FALSE, FALSE},
		{"SCRAM-SHA-1", UCHAR_LEN("n,a==masteruser,,"), NULL, NULL, FALSE, FALSE, FALSE},
		{"SCRAM-SHA-1", UCHAR_LEN("n,,m=testuser,,"), NULL, NULL, FALSE, FALSE, FALSE},
		{"SCRAM-SHA-1", UCHAR_LEN("broken\0input"), NULL, NULL, FALSE, FALSE, FALSE},
		{"SCRAM-SHA-256", UCHAR_LEN("broken\0input"), NULL, NULL, FALSE, FALSE, FALSE},
	};

	test_auth_init();

	string_t *d_token = t_str_new(32);
	str_append_data(d_token,
			UCHAR_LEN("service\0pid\0testuser\0session\0"));
	str_append(d_token,
		   auth_token_get("service","pid","testuser","session"));

	for (unsigned int running_test = 0; running_test < N_ELEMENTS(tests);
	     running_test++) T_BEGIN {
		struct test_case *test_case = &tests[running_test];
		const char *mech_name = test_case->mech_name;
		struct auth_request *request;
		const char *testname = t_strdup_printf("auth mech %s %d/%zu",
						       mech_name,
						       running_test+1,
						       N_ELEMENTS(tests));
		test_begin(testname);

		test_mech_prepare_request(&request, mech_name, &handler,
					  running_test, test_case);

		if (strcmp(mech_name, "APOP") == 0 && test_case->in == NULL)
			test_case->in =	test_mech_construct_apop_challenge(
				request->connect_uid, &test_case->len);
		if (strcmp(mech_name, "DOVECOT-TOKEN") == 0 &&
		    test_case->in == NULL) {
			test_case->in = d_token->data;
			test_case->len = d_token->used;
		}

		if (test_case->expect_error != NULL)
			test_expect_error_string(test_case->expect_error);

		request->state = AUTH_REQUEST_STATE_NEW;
		unsigned char *input_dup = i_malloc(I_MAX(test_case->len, 1));
		memcpy(input_dup, test_case->in, test_case->len);
		request->initial_response = input_dup;
		request->initial_response_len = test_case->len;
		auth_request_initial(request);

		const char *challenge = request->context;

		if (challenge != NULL) {
			test_mech_handle_challenge(request, test_case->in,
						   test_case->len,
						   running_test,
						   test_case->success);
		}

		const char *username = request->fields.user;

		if (request->fields.master_user != NULL)
			username = request->fields.master_user;

		if (!test_case->set_username_before_test &&
		    test_case->success) {
			/* If the username was set by the test logic, do not
			   compare it as it does not give any additional
			   information */
			test_assert_strcmp_idx(test_case->username, username,
					       running_test);
		} else if (!test_case->set_username_before_test &&
			   !test_case->set_cert_username &&
			   !test_case->success) {
			/* If the username is not set by the testlogic and we
			   expect failure, verify that the mechanism failed by
			   checking that the username is not set
			 */
			test_assert_idx(username == NULL, running_test);
		}

		if (test_case->success)
			test_assert_idx(request->failed == FALSE, running_test);
		else
			test_assert_idx(request->failed == TRUE, running_test);

		i_free(input_dup);
		auth_request_unref(&request);

		test_end();
	} T_END;

	test_expect_error_string("oauth2 failed: aborted");
	test_auth_deinit();
}

int main(int argc, char *argv[])
{
	static void (*const test_functions[])(void) = {
		test_mechs,
		NULL
	};
	const enum master_service_flags service_flags =
		MASTER_SERVICE_FLAG_CONFIG_BUILTIN |
		MASTER_SERVICE_FLAG_STANDALONE |
		MASTER_SERVICE_FLAG_STD_CLIENT |
		MASTER_SERVICE_FLAG_DONT_SEND_STATS;
	int ret;

	master_service = master_service_init("test-mech",
					     service_flags, &argc, &argv, "");

	master_service_init_finish(master_service);

	struct ioloop *ioloop = io_loop_create();
	io_loop_set_current(ioloop);
	ret = test_run(test_functions);
	io_loop_destroy(&ioloop);

	master_service_deinit(&master_service);
	return ret;
}
