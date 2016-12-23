/* Copyright (c) 2013-2016 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "test-common.h"
#include "array.h"
#include "str-sanitize.h"
#include "http-auth.h"

struct http_auth_challenge_test {
	const char *scheme;
	const char *data;
	struct http_auth_param *params;
};

struct http_auth_challenges_test {
	const char *challenges_in;

	struct http_auth_challenge_test *challenges;
};

/* Valid auth challenges tests */
static const struct http_auth_challenges_test
valid_auth_challenges_tests[] = {
	{ 
		.challenges_in = "Basic realm=\"WallyWorld\"",
		.challenges = (struct http_auth_challenge_test []) {
			{ .scheme = "Basic",
				.data = NULL,
				.params = (struct http_auth_param []) { 
					{ "realm", "WallyWorld" }, { NULL, NULL }
				}
			},{
				.scheme = NULL
			}
		}
	},{
		.challenges_in = "Digest "
                 "realm=\"testrealm@host.com\", "
                 "qop=\"auth,auth-int\", "
                 "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", "
                 "opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"",
		.challenges = (struct http_auth_challenge_test []) {
			{ .scheme = "Digest",
				.data = NULL,
				.params = (struct http_auth_param []) { 
					{ "realm", "testrealm@host.com" },
					{ "qop", "auth,auth-int" },
					{ "nonce", "dcd98b7102dd2f0e8b11d0f600bfb0c093" },
					{ "opaque", "5ccc069c403ebaf9f0171e9517f40e41" },
					{ NULL, NULL }
				}
			},{
				.scheme = NULL
			}
		}
	},{
		.challenges_in = "Newauth realm=\"apps\", type=1, "
                     "title=\"Login to \\\"apps\\\"\", Basic realm=\"simple\"",
		.challenges = (struct http_auth_challenge_test []) {
			{ .scheme = "Newauth",
				.data = NULL,
				.params = (struct http_auth_param []) { 
					{ "realm", "apps" },
					{ "type", "1" },
					{ "title", "Login to \"apps\"" },
					{ NULL, NULL }
				}
			},{
				.scheme = "Basic",
				.data = NULL,
				.params = (struct http_auth_param []) { 
					{ "realm", "simple" },
					{ NULL, NULL }
				}
			},{
				.scheme = NULL
			}
		}
	}
};

static const unsigned int valid_auth_challenges_test_count =
	N_ELEMENTS(valid_auth_challenges_tests);

static void test_http_auth_challenges_valid(void)
{
	unsigned int i;

	for (i = 0; i < valid_auth_challenges_test_count; i++) T_BEGIN {
		const char *challenges_in;
		ARRAY_TYPE(http_auth_challenge) out;
		const struct http_auth_challenges_test *test;
		bool result;

		test = &valid_auth_challenges_tests[i];
		challenges_in = test->challenges_in;

		test_begin(t_strdup_printf("http auth challenges valid [%d]", i));

		memset(&out, 0, sizeof(out));
		result = (http_auth_parse_challenges
			((const unsigned char *)challenges_in, strlen(challenges_in), 
				&out) > 0);
		test_out(t_strdup_printf("parse `%s'", challenges_in), result);
		if (result) {
			const struct http_auth_challenge *chalo;
			const struct http_auth_challenge_test *chalt;
			unsigned int index;

			index = 0;
			chalt = test->challenges;
			array_foreach(&out, chalo) {
				const struct http_auth_param *paramo, *paramt;
				unsigned int pindex;

				if (chalt != NULL && chalt->scheme != NULL) {
					i_assert(chalo->scheme != NULL);
					test_out(t_strdup_printf("[%d]->scheme = %s",
							index, str_sanitize(chalo->scheme, 80)),
							strcmp(chalo->scheme, chalt->scheme) == 0);
					if (chalo->data == NULL || chalt->data == NULL) {
						test_out(t_strdup_printf("[%d]->data = %s",
							index, str_sanitize(chalo->data, 80)),
							chalo->data == chalt->data);
					} else {
						test_out(t_strdup_printf("[%d]->data = %s",
							index, str_sanitize(chalo->data, 80)),
							strcmp(chalo->data, chalt->data) == 0);
					}
					paramt = chalt->params;
					pindex = 0;
					array_foreach(&chalo->params, paramo) {
						if (paramt->name == NULL) {
							test_out(t_strdup_printf("[%d]->params[%d]: %s = %s",
								index, pindex, str_sanitize(paramo->name, 80),
								str_sanitize(paramo->value, 80)), FALSE);
							break;
						} else {
							test_out(t_strdup_printf("[%d]->params[%d]: %s = %s",
								index, pindex, str_sanitize(paramo->name, 80),
								str_sanitize(paramo->value, 80)),
								strcmp(paramo->name, paramt->name) == 0 &&
								strcmp(paramo->value, paramt->value) == 0);
							paramt++;
						}
						pindex++;
					}
					chalt++;
				}
				index++;
			}
		}

		test_end();
	} T_END;
}

struct http_auth_credentials_test {
	const char *credentials_in;

	const char *scheme;
	const char *data;
	struct http_auth_param *params;
};

/* Valid auth credentials tests */
static const struct http_auth_credentials_test
valid_auth_credentials_tests[] = {
	{ 
		.credentials_in = "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==",
		.scheme = "Basic",
		.data = "QWxhZGRpbjpvcGVuIHNlc2FtZQ==",
		.params = NULL
	},{
		.credentials_in = "Digest username=\"Mufasa\", "
                 "realm=\"testrealm@host.com\", "
                 "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", "
                 "uri=\"/dir/index.html\", "
                 "qop=auth, "
                 "nc=00000001, "
                 "cnonce=\"0a4f113b\", "
                 "response=\"6629fae49393a05397450978507c4ef1\", "
                 "opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"",
		.scheme = "Digest",
		.data = NULL,
		.params = (struct http_auth_param []) {
			{ "username", "Mufasa" },
			{ "realm", "testrealm@host.com" },
			{ "nonce", "dcd98b7102dd2f0e8b11d0f600bfb0c093" },
			{ "uri", "/dir/index.html" },
			{ "qop", "auth" },
			{ "nc", "00000001" },
			{ "cnonce", "0a4f113b" },
			{ "response", "6629fae49393a05397450978507c4ef1" },
			{ "opaque", "5ccc069c403ebaf9f0171e9517f40e41" },
			{ NULL, NULL }
		}
	}
};

static const unsigned int valid_auth_credentials_test_count =
	N_ELEMENTS(valid_auth_credentials_tests);

static void test_http_auth_credentials_valid(void)
{
	unsigned int i;

	for (i = 0; i < valid_auth_credentials_test_count; i++) T_BEGIN {
		const char *credentials_in;
		struct http_auth_credentials out;
		const struct http_auth_credentials_test *test;
		bool result;

		test = &valid_auth_credentials_tests[i];
		credentials_in = test->credentials_in;

		test_begin(t_strdup_printf("http auth credentials valid [%d]", i));

		result = (http_auth_parse_credentials
			((const unsigned char *)credentials_in, strlen(credentials_in), 
				&out) > 0);
		test_out(t_strdup_printf("parse `%s'", credentials_in), result);
		if (result) {
			const struct http_auth_param *paramo, *paramt;
			unsigned int index;

			i_assert(out.scheme != NULL);
			test_out(t_strdup_printf("->scheme = %s",
					str_sanitize(out.scheme, 80)),
					strcmp(out.scheme, test->scheme) == 0);
			if (out.data == NULL || test->data == NULL) {
				test_out(t_strdup_printf("->data = %s",
					str_sanitize(out.data, 80)),
					out.data == test->data);
			} else {
				test_out(t_strdup_printf("->data = %s",
					str_sanitize(out.data, 80)),
					strcmp(out.data, test->data) == 0);
			}
			paramt = test->params;
			index = 0;
			if (array_is_created(&out.params)) {
				array_foreach(&out.params, paramo) {
					if (paramt == NULL || paramt->name == NULL) {
						test_out(t_strdup_printf("->params[%d]: %s = %s",
							index++, str_sanitize(paramo->name, 80),
							str_sanitize(paramo->value, 80)), FALSE);
						break;
					} else {
						test_out(t_strdup_printf("->params[%d]: %s = %s",
							index++, str_sanitize(paramo->name, 80),
							str_sanitize(paramo->value, 80)),
							strcmp(paramo->name, paramt->name) == 0 &&
							strcmp(paramo->value, paramt->value) == 0);
						paramt++;
					}
				}
			}
		}

		test_end();
	} T_END;
}


int main(void)
{
	static void (*const test_functions[])(void) = {
		test_http_auth_challenges_valid,
		test_http_auth_credentials_valid,
		NULL
	};
	return test_run(test_functions);
}
