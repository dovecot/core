/* Copyright (c) 2020 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "auth.h"
#include "str.h"
#include "auth-common.h"
#include "auth-request.h"
#include "auth-request-handler-private.h"
#include "auth-settings.h"
#include "mech-digest-md5-private.h"
#include "otp.h"
#include "mech-otp-skey-common.h"
#include "settings-parser.h"
#include "test-common.h"

#include <unistd.h>
#include <time.h>

#define UCHAR_LEN(str) (const unsigned char *)(str), sizeof(str)-1

extern const struct mech_module mech_anonymous;
extern const struct mech_module mech_apop;
extern const struct mech_module mech_cram_md5;
extern const struct mech_module mech_digest_md5;
extern const struct mech_module mech_dovecot_token;
extern const struct mech_module mech_external;
extern const struct mech_module mech_login;
extern const struct mech_module mech_oauthbearer;
extern const struct mech_module mech_otp;
extern const struct mech_module mech_plain;
extern const struct mech_module mech_scram_sha1;
extern const struct mech_module mech_scram_sha256;
extern const struct mech_module mech_xoauth2;

static struct auth_settings set;
static const char *challenge = NULL;

static void
verify_plain_continue_mock_callback(struct auth_request *request ATTR_UNUSED,
				    verify_plain_callback_t *callback ATTR_UNUSED)
{
	request->failed = FALSE;
}

static void
request_handler_reply_mock_callback(struct auth_request *request ATTR_UNUSED,
				    enum auth_client_result result ATTR_UNUSED,
				    const void *auth_reply ATTR_UNUSED,
				    size_t reply_size ATTR_UNUSED)
{
	if (request->user != NULL && request->mech != &mech_external) {
		request->failed = FALSE;
	}
};

static void
request_handler_reply_continue_mock_callback(struct auth_request *request ATTR_UNUSED,
					     const void *reply ATTR_UNUSED,
					     size_t reply_size ATTR_UNUSED)
{
	challenge = p_strndup(request->pool, reply, reply_size);
}

static void
auth_client_request_mock_callback(const char *reply ATTR_UNUSED,
				  struct auth_client_connection *conn ATTR_UNUSED)
{
}

static void test_mechs_init(void)
{
	process_start_time = time(NULL);

	/* Copy default settings */
	set = *(struct auth_settings *) auth_setting_parser_info.defaults;
	global_auth_settings = &set;
	memset((&set)->username_chars_map, 1, sizeof((&set)->username_chars_map));
	set.username_format = "";

	/* Disable stats */
	set.stats = FALSE;

	/* For tests of digest-md5. */
	set.realms_arr = t_strsplit_spaces("example.com ", " ");
	/* For tests of mech-anonymous. */
	set.anonymous_username = "anonuser";

	i_array_init(&auths, 1);
	struct auth *auth = t_new(struct auth, 1);
	array_push_back(&auths, &auth);
}

static void test_mech_prepare_request(struct auth_request *request,
				      struct auth_request_handler *handler,
				      unsigned int running_test,
				      const char *username)
{
	request->handler = handler;
	request->id = running_test+1;
	request->mech_password = NULL;
	request->state = AUTH_REQUEST_STATE_NEW;
	request->set = global_auth_settings;
	request->connect_uid = running_test;
	handler->refcount = 1;

	auth_fields_add(request->extra_fields, "nodelay", "", 0);
	auth_request_ref(request);
	auth_request_state_count[AUTH_REQUEST_STATE_NEW] = 1;
	challenge = NULL;

	if (username != NULL)
		request->user = p_strdup(request->pool, username);
}

static void test_mech_handle_challenge(struct auth_request *request,
				       const unsigned char *in,
				       size_t in_len,
				       unsigned int running_test,
				       bool expected_success)
{
	if (request->mech == &mech_login) {
		/* We do not care about any specific password just give
		 * the username input as password also in case it's wanted. */
		if (expected_success)
			test_assert_strcmp_idx(challenge, "Password:", running_test);
		else
			test_assert_strcmp_idx(challenge, "Username:", running_test);
	} else if (request->mech == &mech_digest_md5) {
		struct digest_auth_request *digest_request =
			(struct digest_auth_request *) request;
		digest_request->nonce = "OA6MG9tEQGm2hh";
	}
	auth_request_continue(request, in, in_len);
}

static inline const unsigned char *
test_mech_construct_apop_challenge(unsigned int connect_uid, unsigned long *len_r)
{
	string_t *apop_challenge = t_str_new(128);

	str_printfa(apop_challenge,"<%lx.%u.%"PRIdTIME_T"", (unsigned long) getpid(),
		    connect_uid, process_start_time+10);
	str_append_data(apop_challenge, "\0testuser\0responseoflen16-", 26);
	*len_r = apop_challenge->used;
	return apop_challenge->data;
}

static void test_mechs(void)
{
	static struct auth_request_handler handler = {
		.callback = auth_client_request_mock_callback,
		.reply_callback = request_handler_reply_mock_callback,
		.reply_continue_callback = request_handler_reply_continue_mock_callback,
		.verify_plain_continue_callback = verify_plain_continue_mock_callback,
	};

	static struct {
		const struct mech_module *mech;
		const unsigned char *in;
		size_t len;
		const char *username;
		const char *expect_error;
		bool success;
		bool set_username;
	} tests[] = {
		/* Expected to be successful */
		{&mech_anonymous, UCHAR_LEN("\0any \0 bad \0 content"), "anonuser", NULL, TRUE, FALSE},
		{&mech_apop, NULL, 0, "testuser", "All password databases were skipped", TRUE, FALSE},
		{&mech_cram_md5, UCHAR_LEN("testuser mockresponse"), "testuser", "All password databases were skipped", TRUE, FALSE},
		{&mech_digest_md5, UCHAR_LEN("username=\"testuser@example.com\",realm=\"example.com\",nonce=\"OA6MG9tEQGm2hh\",cnonce=\"OA6MHXh6VqTrRk\",nc=00000001,digest-uriresponse=d388dad90d4bbd760a152321f2143af7,qop=\"auth\""), "testuser@example.com", "All password databases were skipped",TRUE, FALSE},
		{&mech_digest_md5, UCHAR_LEN("username=\"testuser@example.com\",realm=\"example.com\",nonce=\"OA6MG9tEQGm2hh\",cnonce=\"OA6MHXh6VqTrRk\",nc=00000001,digest-uriresponse=d388dad90d4bbd760a152321f2143af7,qop=\"auth\",authzid=\"masteruser\""), "testuser@example.com", NULL, TRUE, FALSE},
		{&mech_digest_md5, UCHAR_LEN("username=\"test\xc3\xbaser@example.com\",realm=\"example.com\",nonce=\"OA6MG9tEQGm2hh\",cnonce=\"OA6MHXh6VqTrRk\",nc=00000001,digest-uriresponse=d388dad90d4bbd760a152321f2143af7,qop=\"auth\",authzid=\"masteruser\""), "test\xc3\xbaser@example.com", NULL, TRUE, FALSE},
		{&mech_digest_md5, UCHAR_LEN("username=\"test\xc3\xbaser@example.com\",realm=\"example.com\",nonce=\"OA6MG9tEQGm2hh\",cnonce=\"OA6MHXh6VqTrRk\",charset=\"utf-8\",cipher=unsupported,nc=00000001,digest-uri=imap/server.com,response=d388dad90d4bbd760a152321f2143af7,qop=\"auth\",authzid=\"masteruser\""), "test\xc3\xbaser@example.com", NULL, TRUE, FALSE},
		{&mech_digest_md5, UCHAR_LEN("username=\"testuser\",realm=\"example.com\",nonce=\"OA6MG9tEQGm2hh\",cnonce=\"OA6MHXh6VqTrRk\",charset=\"utf-8\",cipher=unsupported,nc=00000001,digest-uri=imap/server.com,response=d388dad90d4bbd760a152321f2143af7,qop=\"auth\",authzid=\"masteruser\""), "testuser@example.com", NULL, TRUE, FALSE},
		{&mech_external, UCHAR_LEN(""), "testuser", NULL, TRUE, TRUE},
		{&mech_dovecot_token, UCHAR_LEN("service\0pid\0testuser\0session_id\0deadbeef"), "testuser", NULL, TRUE, FALSE},
		{&mech_login, UCHAR_LEN("testuser"), "testuser", NULL, TRUE, FALSE},
		{&mech_plain, UCHAR_LEN("\0testuser\0testpass"), "testuser", NULL, TRUE, FALSE},
		{&mech_plain, UCHAR_LEN("normaluser\0masteruser\0masterpass"), "masteruser", NULL, TRUE, FALSE},
		{&mech_plain, UCHAR_LEN("normaluser\0normaluser\0masterpass"), "normaluser", NULL, TRUE, FALSE},
		{&mech_otp, UCHAR_LEN("somebody\0testuser"), "testuser", "All password databases were skipped", TRUE, FALSE},
		{&mech_otp, UCHAR_LEN("hex:5Bf0 75d9 959d 036f"), "otp_phase_2", NULL, TRUE, TRUE},
		{&mech_otp, UCHAR_LEN("word:BOND FOGY DRAB NE RISE MART"), "otp_phase_2", NULL, TRUE, TRUE},
		{&mech_otp, UCHAR_LEN("init-hex:f6bd 6b33 89b8 7203:md5 499 ke6118:23d1 b253 5ae0 2b7e"), "otp_phase_2", NULL, TRUE, TRUE},
		{&mech_otp, UCHAR_LEN("init-word:END KERN BALM NICK EROS WAVY:md5 499 ke1235:BABY FAIN OILY NIL TIDY DADE"), "otp_phase2", NULL , TRUE, TRUE},
		{&mech_oauthbearer, UCHAR_LEN("n,a=testuser,p=cHJvb2Y=,f=nonstandart\x01host=server\x01port=143\x01""auth=Bearer vF9dft4qmTc2Nvb3RlckBhbHRhdmlzdGEuY29tCg==\x01\x01"), "testuser", NULL, TRUE, FALSE},
		{&mech_scram_sha1, UCHAR_LEN("n,,n=testuser,r=rOprNGfwEbeRWgbNEkqO"), "testuser", "All password databases were skipped", TRUE, FALSE},
		{&mech_scram_sha256, UCHAR_LEN("n,,n=testuser,r=rOprNGfwEbeRWgbNEkqO"), "testuser",  "All password databases were skipped", TRUE, FALSE},
		{&mech_xoauth2, UCHAR_LEN("user=testuser\x01""auth=Bearer vF9dft4qmTc2Nvb3RlckBhdHRhdmlzdGEuY29tCg==\x01\x01"), "testuser", NULL, TRUE, FALSE},

		/* Below tests are expected to fail */
		/* Empty input tests*/
		{&mech_apop, UCHAR_LEN(""), NULL, NULL, FALSE, FALSE},
		{&mech_cram_md5, UCHAR_LEN(""), NULL, NULL, FALSE, FALSE},
		{&mech_digest_md5, UCHAR_LEN(""), NULL, NULL, FALSE, FALSE},
		{&mech_dovecot_token, UCHAR_LEN(""), NULL, NULL, FALSE, FALSE},
		{&mech_external, UCHAR_LEN(""), "testuser", NULL, FALSE, TRUE},
		{&mech_external, UCHAR_LEN(""), NULL, NULL, FALSE, FALSE},
		{&mech_login, UCHAR_LEN(""), NULL, NULL, FALSE, FALSE},
		{&mech_otp, UCHAR_LEN(""), NULL, "invalid input", FALSE, FALSE},
		{&mech_otp, UCHAR_LEN(""), "testuser", "unsupported response type", FALSE, TRUE},
		{&mech_plain, UCHAR_LEN(""), NULL, NULL, FALSE, FALSE},
		{&mech_oauthbearer, UCHAR_LEN(""), NULL, NULL, FALSE, FALSE},
		{&mech_xoauth2, UCHAR_LEN(""), NULL, NULL, FALSE, FALSE},
		{&mech_scram_sha1, UCHAR_LEN(""), NULL, NULL, FALSE, FALSE},
		{&mech_scram_sha256, UCHAR_LEN(""), NULL, NULL, FALSE, FALSE},

		/* Bad input tests*/
		{&mech_apop, UCHAR_LEN("1.1.1\0test\0user\0response"), NULL, NULL, FALSE, FALSE},
		{&mech_apop, UCHAR_LEN("1.1.1\0testuser\0tooshort"), NULL, NULL, FALSE, FALSE},
		{&mech_apop, UCHAR_LEN("1.1.1\0testuser\0responseoflen16-"), NULL, NULL, FALSE, FALSE},
		{&mech_apop, UCHAR_LEN("1.1.1"), NULL, NULL, FALSE, FALSE},
		{&mech_cram_md5, UCHAR_LEN("testuser\0response"), NULL, NULL, FALSE, FALSE},

		/* Covering most of the digest md5 parsing */
		{&mech_digest_md5, UCHAR_LEN("username=\"testuser@example.com\",realm=\"example.com\",cnonce=\"OA6MHXh6VqTrRk\",response=d388dad90d4bbd760a152321f2143af7,qop=\"auth\""), NULL, NULL, FALSE, FALSE},
		{&mech_digest_md5, UCHAR_LEN("realm=\"example.com\",cnonce=\"OA6MHXh6VqTrRk\",nonce=\"OA6MG9tEQGm2hh\""), NULL, NULL, FALSE, FALSE},
		{&mech_digest_md5, UCHAR_LEN("username=\"testuser@example.com\",realm=\"example.com\", nonce=\"OA6MG9tEQGm2hh\""), NULL, NULL, FALSE, FALSE},
		{&mech_digest_md5, UCHAR_LEN("qop=\"auth-int\""), NULL, NULL, FALSE, FALSE},
		{&mech_digest_md5, UCHAR_LEN("qop=\"auth-int\""), NULL, NULL, FALSE, FALSE},
		{&mech_digest_md5, UCHAR_LEN("qop=\"auth-conf\",\"cipher=rc4\""), NULL, NULL, FALSE, FALSE},
		{&mech_digest_md5, UCHAR_LEN("cnonce=\"OA6MHXh6VqTrRk\",cnonce=\"OA6MHXh6VqTrRk\""), NULL, NULL, FALSE, FALSE},
		{&mech_digest_md5, UCHAR_LEN("cnonce=\"\""), NULL, NULL, FALSE, FALSE},
		{&mech_digest_md5, UCHAR_LEN("nonce=\"not matching\""), NULL, NULL, FALSE, FALSE},
		{&mech_digest_md5, UCHAR_LEN("nc=00000001,nc=00000002"), NULL, NULL, FALSE, FALSE},
		{&mech_digest_md5, UCHAR_LEN("nc=NAN"), NULL, NULL, FALSE, FALSE},
		{&mech_digest_md5, UCHAR_LEN("nc=00000002"), NULL, NULL, FALSE, FALSE},
		{&mech_digest_md5, UCHAR_LEN("cipher=unsupported"), NULL, NULL, FALSE, FALSE},
		{&mech_digest_md5, UCHAR_LEN("digest-uri="), NULL, NULL, FALSE, FALSE},
		{&mech_digest_md5, UCHAR_LEN("username=\"\""), NULL, NULL, FALSE, FALSE},
		{&mech_digest_md5, UCHAR_LEN("username=\"a\",username=\"b\""), NULL, NULL, FALSE, FALSE},
		{&mech_digest_md5, UCHAR_LEN("response=broken"), NULL, NULL, FALSE, FALSE},
		{&mech_digest_md5, UCHAR_LEN("maxbuf=32,maxbuf=1024"), NULL, NULL, FALSE, FALSE},
		{&mech_digest_md5, UCHAR_LEN("maxbuf=broken"), NULL, NULL, FALSE, FALSE},
		{&mech_digest_md5, UCHAR_LEN("authzid=\"somebody\",authzid=\"else\""), NULL, NULL, FALSE, FALSE},
		{&mech_digest_md5, UCHAR_LEN("authzid=\"\""), NULL, NULL, FALSE, FALSE},
		{&mech_digest_md5, UCHAR_LEN("charset=unsupported"), NULL, NULL, FALSE, FALSE},
		{&mech_digest_md5, UCHAR_LEN("qop=unsupported"), NULL, NULL, FALSE, FALSE},

		/* Too much nuls */
		{&mech_dovecot_token, UCHAR_LEN("service\0pid\0fail\0se\0ssion_id\0deadbeef"), NULL , NULL, FALSE, FALSE},
		{&mech_login, UCHAR_LEN("test user\0user"), NULL, NULL, TRUE, FALSE},
		{&mech_oauthbearer, UCHAR_LEN("n,a==testuser,\x01""auth=Bearer token\x01\x01"), NULL, NULL, FALSE, FALSE},
		{&mech_oauthbearer, UCHAR_LEN("n,a=testuser,f=non-standard\x01""auth=Bearer token\x01\x01"), "testuser", NULL, FALSE, FALSE},
		{&mech_oauthbearer, UCHAR_LEN("n,a=testuser\x01""auth=token\x01\x01"), "testuser", NULL, FALSE, FALSE},
		{&mech_xoauth2, UCHAR_LEN("testuser\x01auth=Bearer token\x01\x01"), NULL, NULL, FALSE, FALSE},
		/* does not start with [B|b]earer */
		{&mech_xoauth2, UCHAR_LEN("user=testuser\x01""auth=token\x01\x01"), "testuser", NULL, FALSE, FALSE},
		/* Too much nuls */
		{&mech_plain, UCHAR_LEN("\0fa\0il\0ing\0withthis"), NULL, NULL, FALSE, FALSE},
		{&mech_plain, UCHAR_LEN("failingwiththis"), NULL, NULL, FALSE, FALSE},
		{&mech_plain, UCHAR_LEN("failing\0withthis"), NULL, NULL, FALSE, FALSE},
		{&mech_otp, UCHAR_LEN("someb\0ody\0testuser"), NULL, "invalid input", FALSE, FALSE},
		/* phase 2 */
		{&mech_otp, UCHAR_LEN("someb\0ody\0testuser"), "testuser", NULL, FALSE, TRUE},
		{&mech_scram_sha1, UCHAR_LEN("c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts="), NULL, NULL, FALSE, FALSE},
		{&mech_scram_sha1, UCHAR_LEN("iws0X8v3Bz2T0CJGbJQyF0X+HI4Ts=,,,,"), NULL, NULL, FALSE, FALSE},
		{&mech_scram_sha1, UCHAR_LEN("n,a=masteruser,,"), NULL, NULL, FALSE, FALSE},
		{&mech_scram_sha1, UCHAR_LEN("n,a==masteruser,,"), NULL, NULL, FALSE, FALSE},
		{&mech_scram_sha1, UCHAR_LEN("n,,m=testuser,,"), NULL, NULL, FALSE, FALSE},
		{&mech_scram_sha1, UCHAR_LEN("broken\0input"), NULL, NULL, FALSE, FALSE},
		{&mech_scram_sha256, UCHAR_LEN("broken\0input"), NULL, NULL, FALSE, FALSE},
	};

	test_mechs_init();

	for (unsigned int running_test = 0; running_test < N_ELEMENTS(tests);
	     running_test++) T_BEGIN {
		const struct mech_module *mech = tests[running_test].mech;
		struct auth_request *request;
		const char *testname = t_strdup_printf("auth mech %s %d/%lu",
						       mech->mech_name,
						       running_test+1,
						       N_ELEMENTS(tests));
		test_begin(testname);

		request = auth_request_new(mech,  NULL);
		test_mech_prepare_request(request, &handler, running_test,
					  tests[running_test].set_username ?
					  tests[running_test].username : NULL);

		if (mech == &mech_apop && tests[running_test].in == NULL)
			tests[running_test].in =
				test_mech_construct_apop_challenge(request->connect_uid,
								   &tests[running_test].len);

		if (tests[running_test].expect_error != NULL)
			test_expect_error_string(tests[running_test].expect_error);

		request->state = AUTH_REQUEST_STATE_NEW;
		request->initial_response = tests[running_test].in;
		request->initial_response_len = tests[running_test].len;
		auth_request_initial(request);

		if (challenge != NULL) {
			test_mech_handle_challenge(request, tests[running_test].in,
						   tests[running_test].len,
						   running_test,
						   tests[running_test].success);
		}

		if (!tests[running_test].set_username)
			test_assert_strcmp_idx(tests[running_test].username, request->user,
					       running_test);
		else if (!tests[running_test].set_username && !tests[running_test].success)
			test_assert_idx(request->user == NULL, running_test);
		else
			test_assert_idx(!request->failed, running_test);

		event_unref(&request->event);
		event_unref(&request->mech_event);
		mech->auth_free(request);

		test_end();
	} T_END;
	mech_otp_deinit();
	array_free(&auths);
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_mechs,
		NULL
	};

	return test_run(test_functions);
}
