/* Copyright (c) 2020 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "str.h"
#include "ostream.h"
#include "hmac.h"
#include "sha2.h"
#include "base64.h"
#include "randgen.h"
#include "array.h"
#include "json-parser.h"
#include "iso8601-date.h"
#include "oauth2.h"
#include "oauth2-private.h"
#include "dcrypt.h"
#include "dict.h"
#include "dict-private.h"
#include "test-common.h"
#include "unlink-directory.h"

#include <sys/stat.h>
#include <sys/types.h>

#define base64url_encode_str(str, dest) \
	base64url_encode(BASE64_ENCODE_FLAG_NO_PADDING, (size_t)-1, (str), \
			 strlen((str)), (dest))

/**
 * Test keypair used only for this test.
 */
static const char *rsa_public_key =
"-----BEGIN PUBLIC KEY-----\n"
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzyis1ZjfNB0bBgKFMSv\n"
"vkTtwlvBsaJq7S5wA+kzeVOVpVWwkWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHc\n"
"aT92whREFpLv9cj5lTeJSibyr/Mrm/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIy\n"
"tvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0\n"
"e+lf4s4OxQawWD79J9/5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWb\n"
"V6L11BWkpzGXSW4Hv43qa+GSYOD2QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9\n"
"MwIDAQAB\n"
"-----END PUBLIC KEY-----";
static const char *rsa_private_key =
"-----BEGIN PRIVATE KEY-----\n"
"MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCfPKKzVmN80HRs\n"
"GAoUxK++RO3CW8GxomrtLnAD6TN5U5WlVbCRZ1WFrizfxcz+lr/Kvjtq/v7PdVOa\n"
"8NHIAdxpP3bCFEQWku/1yPmVN4lKJvKv8yub9i2MJlVaBo5giHCtfAouo+v/XWKd\n"
"awCR8jK28dZPFlgRxcuABcW5S5pLe4X2ASI1DDMZNTW/QWqSpMGvgHydbccI3jtd\n"
"S7S3xjR76V/izg7FBrBYPv0n3/l3dHLS9tXcCbUW0YmIm87BGwh9UKEOlhK1NwdM\n"
"Iyq29ZtXovXUFaSnMZdJbge/jepr4ZJg4PZBTrwxvn2hKTY4H4G04ukmh+ZsYQaC\n"
"+bDIIj0zAgMBAAECggEAKIBGrbCSW2O1yOyQW9nvDUkA5EdsS58Q7US7bvM4iWpu\n"
"DIBwCXur7/VuKnhn/HUhURLzj/JNozynSChqYyG+CvL+ZLy82LUE3ZIBkSdv/vFL\n"
"Ft+VvvRtf1EcsmoqenkZl7aN7HD7DJeXBoz5tyVQKuH17WW0fsi9StGtCcUl+H6K\n"
"zV9Gif0Kj0uLQbCg3THRvKuueBTwCTdjoP0PwaNADgSWb3hJPeLMm/yII4tIMGbO\n"
"w+xd9wJRl+ZN9nkNtQMxszFGdKjedB6goYLQuP0WRZx+YtykaVJdM75bDUvsQar4\n"
"9Pc21Fp7UVk/CN11DX/hX3TmTJAUtqYADliVKkTbCQKBgQDLU48tBxm3g1CdDM/P\n"
"ZIEmpA3Y/m7e9eX7M1Uo/zDh4G/S9a4kkX6GQY2dLFdCtOS8M4hR11Io7MceBKDi\n"
"djorTZ5zJPQ8+b9Rm+1GlaucGNwRW0cQk2ltT2ksPmJnQn2xvM9T8vE+a4A/YGzw\n"
"mZOfpoVGykWs/tbSzU2aTaOybQKBgQDIfRf6OmirGPh59l+RSuDkZtISF/51mCV/\n"
"S1M4DltWDwhjC2Y2T+meIsb/Mjtz4aVNz0EHB8yvn0TMGr94Uwjv4uBdpVSwz+xL\n"
"hHL7J4rpInH+i0gxa0N+rGwsPwI8wJG95wLY+Kni5KCuXQw55uX1cqnnsahpRZFZ\n"
"EerBXhjqHwKBgBmEjiaHipm2eEqNjhMoOPFBi59dJ0sCL2/cXGa9yEPA6Cfgv49F\n"
"V0zAM2azZuwvSbm4+fXTgTMzrDW/PPXPArPmlOk8jQ6OBY3XdOrz48q+b/gZrYyO\n"
"A6A9ZCSyW6U7+gxxds/BYLeFxF2v21xC2f0iZ/2faykv/oQMUh34en/tAoGACqVZ\n"
"2JexZyR0TUWf3X80YexzyzIq+OOTWicNzDQ29WLm9xtr2gZ0SUlfd72bGpQoyvDu\n"
"awkm/UxfwtbIxALkvpg1gcN9s8XWrkviLyPyZF7H3tRWiQlBFEDjnZXa8I7pLkRO\n"
"Cmdp3fp17cxTEeAI5feovfzZDH39MdWZuZrdh9ECgYBTEv8S7nK8wrxIC390kroV\n"
"52eBwzckQU2mWa0thUtaGQiU1EYPCSDcjkrLXwB72ft0dW57KyWtvrB6rt1ORgOL\n"
"eI5hFbwdGQhCHTrAR1vG3SyFPMAm+8JB+sGOD/fvjtZKx//MFNweKFNEF0C/o6Z2\n"
"FXj90PlgF8sCQut36ZfuIQ==\n"
"-----END PRIVATE KEY-----";

static buffer_t *hs_sign_key = NULL;

static struct dict *keys_dict = NULL;

static bool skip_dcrypt = FALSE;

static struct oauth2_validation_key_cache *key_cache = NULL;

static int parse_jwt_token(struct oauth2_request *req, const char *token,
			   bool *is_jwt_r, const char **error_r)
{
	struct oauth2_settings set;
	set.scope = "mail";
	set.key_dict = keys_dict;
	set.key_cache = key_cache;
	i_zero(req);
	req->pool = pool_datastack_create();
	req->set = &set;
	t_array_init(&req->fields, 8);
	return oauth2_try_parse_jwt(&set, token, &req->fields, is_jwt_r, error_r);
}

static void test_jwt_token(const char *token)
{
	/* then see what the parser likes it */
	struct oauth2_request req;
	const char *error = NULL;
	bool is_jwt;
	test_assert(parse_jwt_token(&req, token, &is_jwt, &error) == 0);
	test_assert(is_jwt == TRUE);
	test_assert(error == NULL);

	/* check fields */
	test_assert(array_is_created(&req.fields));
	if (array_is_created(&req.fields)) {
		const struct oauth2_field *field;
		bool got_sub = FALSE;
		array_foreach(&req.fields, field) {
			if (strcmp(field->name, "sub") == 0) {
				test_assert_strcmp(field->value, "testuser");
				got_sub = TRUE;
			}
		}
		test_assert(got_sub == TRUE);
	}

	if (error != NULL)
		i_error("%s", error);
}

static buffer_t *create_jwt_token_kid(const char *algo, const char *kid)
{
	/* make a token */
	buffer_t *tokenbuf = t_buffer_create(64);

	/* header */
	base64url_encode_str(t_strdup_printf(
				"{\"alg\":\"%s\",\"typ\":\"JWT\",\"kid\":\"%s\"}",
				 algo, kid), tokenbuf);
	buffer_append(tokenbuf, ".", 1);

	/* body */
	base64url_encode_str(t_strdup_printf("{\"sub\":\"testuser\","\
				"\"iat\":%"PRIdTIME_T","
				"\"exp\":%"PRIdTIME_T"}",
					time(NULL),
					time(NULL)+600), tokenbuf);
	return tokenbuf;
}

static buffer_t *create_jwt_token(const char *algo)
{
	/* make a token */
	buffer_t *tokenbuf = t_buffer_create(64);

	/* header */
	base64url_encode_str(t_strdup_printf(
				"{\"alg\":\"%s\",\"typ\":\"JWT\"}", algo), tokenbuf);
	buffer_append(tokenbuf, ".", 1);

	/* body */
	base64url_encode_str(t_strdup_printf("{\"sub\":\"testuser\","\
				"\"iat\":%"PRIdTIME_T","
				"\"exp\":%"PRIdTIME_T"}",
					time(NULL),
					time(NULL)+600), tokenbuf);
	return tokenbuf;
}

static void append_key_value(string_t *dest, const char *key, const char *value, bool str)
{
	str_append_c(dest, '"');
	json_append_escaped(dest, key);
	str_append(dest, "\":");
	if (str)
		str_append_c(dest, '"');
	json_append_escaped(dest, value);
	if (str)
		str_append_c(dest, '"');

}

static buffer_t *create_jwt_token_fields(const char *algo, time_t exp, time_t iat,
					 time_t nbf, ARRAY_TYPE(oauth2_field) *fields)
{
	const struct oauth2_field *field;
	buffer_t *tokenbuf = t_buffer_create(64);
	base64url_encode_str(t_strdup_printf(
				"{\"alg\":\"%s\",\"typ\":\"JWT\"}", algo), tokenbuf);
	buffer_append(tokenbuf, ".", 1);
	string_t *bodybuf = t_str_new(64);
	str_append_c(bodybuf, '{');
	if (exp > 0) {
		append_key_value(bodybuf, "exp", dec2str(exp), FALSE);
	}
	if (iat > 0) {
		if (exp > 0)
			str_append_c(bodybuf, ',');
		append_key_value(bodybuf, "iat", dec2str(iat), FALSE);
	}
	if (nbf > 0) {
		if (exp > 0 || iat > 0)
			str_append_c(bodybuf, ',');
		append_key_value(bodybuf, "nbf", dec2str(nbf), FALSE);
	}
	array_foreach(fields, field) {
		if (str_data(bodybuf)[bodybuf->used-1] != '{')
			str_append_c(bodybuf, ',');
		append_key_value(bodybuf, field->name, field->value, TRUE);
	}
	str_append_c(bodybuf, '}');
	base64url_encode_str(str_c(bodybuf), tokenbuf);

	return tokenbuf;
}

#define save_key(algo, key) save_key_to(algo, "default", (key))
static void save_key_to(const char *algo, const char *name, const char *keydata)
{
	const char *error;
	struct dict_transaction_context *ctx = dict_transaction_begin(keys_dict);
	dict_set(ctx, t_strconcat(DICT_PATH_SHARED, algo, "/", name, NULL), keydata);
	if (dict_transaction_commit(&ctx, &error) < 0)
		i_error("dict_set(%s) failed: %s", name, error);
}

static void sign_jwt_token_hs256(buffer_t *tokenbuf, buffer_t *key)
{
	i_assert(key != NULL);
	buffer_t *sig = t_hmac_buffer(&hash_method_sha256, key->data, key->used,
				      tokenbuf);
	buffer_append(tokenbuf, ".", 1);
	base64url_encode(BASE64_ENCODE_FLAG_NO_PADDING, (size_t)-1,
			 sig->data, sig->used, tokenbuf);
}

static void test_jwt_hs_token(void)
{
	test_begin("JWT HMAC token");

	/* make a token */
	buffer_t *tokenbuf = create_jwt_token("HS256");
	/* sign it */
	sign_jwt_token_hs256(tokenbuf, hs_sign_key);
	test_jwt_token(str_c(tokenbuf));

	test_end();
}

static void test_jwt_broken_token(void)
{
	struct test_cases {
		const char *token;
		bool is_jwt;
	} test_cases[] = {
		{ /* empty token */
			.token = "",
			.is_jwt = FALSE
		},
		{ /* not base64 */
			.token = "{\"alg\":\"HS256\":\"typ\":\"JWT\"}",
			.is_jwt = FALSE
		},
		{ /* not jwt */
			.token = "aGVsbG8sIHdvcmxkCg",
			.is_jwt = FALSE
		},
		{ /* no alg field */
			.token = "eyJ0eXAiOiAiSldUIn0",
			.is_jwt = FALSE
		},
		{ /* no typ field */
			.token = "eyJhbGciOiAiSFMyNTYifQ",
			.is_jwt = FALSE
		},
		{ /* typ field is wrong */
			.token = "eyJ0eXAiOiAiand0IiwgImFsZyI6ICJIUzI1NiJ9."
				 "eyJhbGdvIjogIldURiIsICJ0eXAiOiAiSldUIn0."
				 "q2wwwWWJVJxqw-J3uQ0DdlIyWfoZ7Z0QrdzvMW_B-jo",
			.is_jwt = FALSE
		},
		{ /* unknown algorithm */
			.token = "eyJ0eXAiOiAiSldUIiwgImFsZyI6ICJXVEYifQ."
				 "eyJhbGdvIjogIldURiIsICJ0eXAiOiAiSldUIn0."
				 "q2wwwWWJVJxqw-J3uQ0DdlIyWfoZ7Z0QrdzvMW_B-jo",
			.is_jwt = TRUE
		},
		{ /* truncated base64 */
			.token  = "yJhbGciOiJIUzI1NiIsInR5",
			.is_jwt = FALSE
		},
		{ /* missing body and signature */
			.token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
			.is_jwt = FALSE
		},
		{ /* empty body and signature */
			.token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..",
			.is_jwt = TRUE
		},
		{ /* empty signature */
			.token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
				 "eyJleHAiOjE1ODEzMzA3OTN9.",
			.is_jwt = TRUE
		},
		{ /* bad signature */
			.token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
				 "eyJleHAiOjE1ODEzMzA3OTN9."
				 "q2wwwWWJVJxqw-J3uQ0DdlIyWfoZ7Z0QrdzvMW_B-jo",
			.is_jwt = TRUE
		},
	};

	test_begin("JWT broken tokens");

	for (size_t i = 0; i < N_ELEMENTS(test_cases); i++) T_BEGIN {
		struct test_cases *test_case = &test_cases[i];
		struct oauth2_request req;
		const char *error = NULL;
		bool is_jwt;
		test_assert_idx(parse_jwt_token(&req, test_case->token, &is_jwt, &error) != 0, i);
		test_assert_idx(test_case->is_jwt == is_jwt, i);
		test_assert_idx(error != NULL, i);
	} T_END;

	test_end();
}

static void test_jwt_bad_valid_token(void)
{
	test_begin("JWT bad token tests");
	time_t now = time(NULL);

	struct test_cases {
		time_t exp;
		time_t iat;
		time_t nbf;
		const char *key_values[20];
		const char *error;
	} test_cases[] =
	{
		{ /* "empty" token */
			.exp = 0,
			.iat = 0,
			.nbf = 0,
			.key_values = { NULL },
			.error = "Missing 'sub' field",
		},
		{ /* missing sub field */
			.exp = now+500,
			.iat = 0,
			.nbf = 0,
			.key_values = { NULL },
			.error = "Missing 'sub' field",
		},
		{ /* non-ISO date as iat */
			.exp = now+500,
			.iat = 0,
			.nbf = 0,
			.key_values = { "sub", "testuser", "iat", "1.1.2019 16:00", NULL },
			.error = "Malformed 'iat' field"
		},
		{ /* expired token */
			.exp = now-500,
			.iat = 0,
			.nbf = 0,
			.key_values = { "sub", "testuser", NULL },
			.error = "Token has expired",
		},
		{ /* future token */
			.exp = now+1000,
			.iat = now+500,
			.nbf = 0,
			.key_values = { "sub", "testuser", NULL },
			.error = "Token is issued in future",
		},
		{ /* token not valid yet */
			.exp = now+500,
			.iat = now,
			.nbf = now+250,
			.key_values = { "sub", "testuser", NULL },
			.error = "Token is not valid yet",
		},
	};

	for (size_t i = 0; i < N_ELEMENTS(test_cases); i++) T_BEGIN {
		const struct test_cases *test_case = &test_cases[i];
		const char *key = NULL;
		ARRAY_TYPE(oauth2_field) fields;
		t_array_init(&fields, 8);
		for (const char *const *value = test_case->key_values; *value != NULL; value++) {
			if (key == NULL) {
				key = *value;
			} else {
				struct oauth2_field *field =
					array_append_space(&fields);
				field->name = key;
				field->value = *value;
				key = NULL;
			}
		}

		buffer_t *tokenbuf =
			create_jwt_token_fields("HS256", test_case->exp, test_case->iat,
						test_case->nbf, &fields);
		sign_jwt_token_hs256(tokenbuf, hs_sign_key);
		struct oauth2_request req;
		const char *error = NULL;
		bool is_jwt;
		test_assert_idx(parse_jwt_token(&req, str_c(tokenbuf), &is_jwt, &error) != 0, i);
		test_assert_idx(is_jwt == TRUE, i);
		if (test_case->error != NULL) {
			test_assert_strcmp(test_case->error, error);
		}
		test_assert(error != NULL);
	} T_END;

	test_end();
}

static void test_jwt_dates(void)
{
	test_begin("JWT Token dates");

	/* simple check to make sure ISO8601 dates work too */
	ARRAY_TYPE(oauth2_field) fields;
	t_array_init(&fields, 8);
	struct oauth2_field *field;
	struct tm tm_b;
	struct tm *tm;
	time_t now = time(NULL);
	time_t exp = now+500;
	time_t nbf = now-250;
	time_t iat = now-500;

	field = array_append_space(&fields);
	field->name = "sub";
	field->value = "testuser";
	field = array_append_space(&fields);
	field->name = "exp";
	tm = gmtime_r(&exp, &tm_b);
	field->value = iso8601_date_create_tm(tm, INT_MAX);
	field = array_append_space(&fields);
	field->name = "nbf";
	tm = gmtime_r(&nbf, &tm_b);
	field->value = iso8601_date_create_tm(tm, INT_MAX);
	field = array_append_space(&fields);
	field->name = "iat";
	tm = gmtime_r(&iat, &tm_b);
	field->value = iso8601_date_create_tm(tm, INT_MAX);
	buffer_t *tokenbuf = create_jwt_token_fields("HS256", 0, 0, 0, &fields);
	sign_jwt_token_hs256(tokenbuf, hs_sign_key);
	test_jwt_token(str_c(tokenbuf));

	str_truncate(tokenbuf, 0);
        base64url_encode_str("{\"alg\":\"HS256\",\"typ\":\"JWT\"}", tokenbuf);
	str_append_c(tokenbuf, '.');
	base64url_encode_str(t_strdup_printf("{\"sub\":\"testuser\","
					     "\"exp\":%"PRIdTIME_T","
				             "\"nbf\":0,\"iat\":%"PRIdTIME_T"}",
					     exp, iat),
			     tokenbuf);
	sign_jwt_token_hs256(tokenbuf, hs_sign_key);
	test_jwt_token(str_c(tokenbuf));

	test_end();
}

static void test_jwt_key_files(void)
{
	test_begin("JWT key id");
	/* write HMAC secrets */
	struct oauth2_request req;
	bool is_jwt;
	const char *error = NULL;

	buffer_t *secret = t_buffer_create(32);
	void *ptr = buffer_append_space_unsafe(secret, 32);
	random_fill(ptr, 32);
	buffer_t *b64_key = t_base64_encode(0, (size_t)-1, secret->data, secret->used);
	save_key_to("HS256", "first", str_c(b64_key));
	buffer_t *secret2 = t_buffer_create(32);
	ptr = buffer_append_space_unsafe(secret2, 32);
	random_fill(ptr, 32);
	b64_key = t_base64_encode(0, (size_t)-1, secret2->data, secret2->used);
	save_key_to("HS256", "second", str_c(b64_key));

	/* create and sign token */
	buffer_t *token_1 = create_jwt_token_kid("HS256", "first");
	buffer_t *token_2 = create_jwt_token_kid("HS256", "second");
	buffer_t *token_3 = create_jwt_token_kid("HS256", "missing");
	buffer_t *token_4 = create_jwt_token_kid("HS256", "");

	sign_jwt_token_hs256(token_1, secret);
	sign_jwt_token_hs256(token_2, secret2);
	sign_jwt_token_hs256(token_3, secret);
	sign_jwt_token_hs256(token_4, secret);

	test_jwt_token(str_c(token_1));
	test_jwt_token(str_c(token_2));

	test_assert(parse_jwt_token(&req, str_c(token_3), &is_jwt, &error) != 0);
	test_assert(is_jwt == TRUE);
	test_assert_strcmp(error, "HS256 key 'missing' not found");
	test_assert(parse_jwt_token(&req, str_c(token_4), &is_jwt, &error) != 0);
	test_assert(is_jwt == TRUE);
	test_assert_strcmp(error, "'kid' field is empty");

	test_end();
}

static void test_jwt_rs_token(void)
{
	const char *error;
	if (skip_dcrypt)
		return;

	test_begin("JWT RSA token");
	/* write public key to file */
	oauth2_validation_key_cache_evict(key_cache, "default");
	save_key("RS256", rsa_public_key);

	buffer_t *tokenbuf = create_jwt_token("RS256");
	/* sign token */
	buffer_t *sig = t_buffer_create(64);
	struct dcrypt_private_key *key;
	if (!dcrypt_key_load_private(&key, rsa_private_key, NULL, NULL, &error) ||
	    !dcrypt_sign(key, "sha256", DCRYPT_SIGNATURE_FORMAT_DSS,
			 tokenbuf->data, tokenbuf->used, sig,
			 DCRYPT_PADDING_RSA_PKCS1, &error)) {
		i_error("dcrypt signing failed: %s", error);
		exit(1);
	}
	dcrypt_key_unref_private(&key);
	/* convert to base64 */
	buffer_append(tokenbuf, ".", 1);
	base64url_encode(BASE64_ENCODE_FLAG_NO_PADDING, (size_t)-1,
			 sig->data, sig->used, tokenbuf);

	test_jwt_token(str_c(tokenbuf));

	test_end();
}

static void test_jwt_ps_token(void)
{
	const char *error;
	if (skip_dcrypt)
		return;

	test_begin("JWT RSAPSS token");
	/* write public key to file */
	oauth2_validation_key_cache_evict(key_cache, "default");
	save_key("PS256", rsa_public_key);

	buffer_t *tokenbuf = create_jwt_token("PS256");
	/* sign token */
	buffer_t *sig = t_buffer_create(64);
	struct dcrypt_private_key *key;
	if (!dcrypt_key_load_private(&key, rsa_private_key, NULL, NULL, &error) ||
	    !dcrypt_sign(key, "sha256", DCRYPT_SIGNATURE_FORMAT_DSS,
			 tokenbuf->data, tokenbuf->used, sig,
			 DCRYPT_PADDING_RSA_PKCS1_PSS, &error)) {
		i_error("dcrypt signing failed: %s", error);
		exit(1);
	}
	dcrypt_key_unref_private(&key);
	/* convert to base64 */
	buffer_append(tokenbuf, ".", 1);
	base64url_encode(BASE64_ENCODE_FLAG_NO_PADDING, (size_t)-1,
			 sig->data, sig->used, tokenbuf);

	test_jwt_token(str_c(tokenbuf));

	test_end();
}

static void test_jwt_ec_token(void)
{
	const char *error;
	if (skip_dcrypt)
		return;

	test_begin("JWT ECDSA token");
	struct dcrypt_keypair pair;
	i_zero(&pair);
	if (!dcrypt_keypair_generate(&pair, DCRYPT_KEY_EC, 0,
				     "prime256v1", &error)) {
		i_error("dcrypt keypair generate failed: %s", error);
		exit(1);
	}
	/* export public key */
	buffer_t *keybuf = t_buffer_create(256);
	if (!dcrypt_key_store_public(pair.pub, DCRYPT_FORMAT_PEM, keybuf, &error)) {
		i_error("dcrypt key store failed: %s", error);
		exit(1);
	}
	oauth2_validation_key_cache_evict(key_cache, "default");
	save_key("ES256", str_c(keybuf));

	buffer_t *tokenbuf = create_jwt_token("ES256");
	/* sign token */
	buffer_t *sig = t_buffer_create(64);
	if (!dcrypt_sign(pair.priv, "sha256", DCRYPT_SIGNATURE_FORMAT_X962,
			 tokenbuf->data, tokenbuf->used, sig,
			 DCRYPT_PADDING_DEFAULT, &error)) {
		i_error("dcrypt signing failed: %s", error);
		exit(1);
	}
	dcrypt_keypair_unref(&pair);
	/* convert to base64 */
	buffer_append(tokenbuf, ".", 1);
	base64url_encode(BASE64_ENCODE_FLAG_NO_PADDING, (size_t)-1,
			 sig->data, sig->used, tokenbuf);
	test_jwt_token(str_c(tokenbuf));

	test_end();
}

static void test_do_init(void)
{
	const char *error;
	struct dcrypt_settings dcrypt_set = {
		.module_dir = "../lib-dcrypt/.libs",
	};
	struct dict_settings dict_set = {
		.username = "testuser",
		.value_type = DICT_DATA_TYPE_STRING,
		.base_dir = ".",
	};
	i_unlink_if_exists(".keys");
	dict_driver_register(&dict_driver_file);
	if (dict_init("file:.keys", &dict_set, &keys_dict, &error) < 0)
		i_fatal("dict_init(file:.keys): %s", error);
	if (!dcrypt_initialize(NULL, &dcrypt_set, &error)) {
		i_error("No functional dcrypt backend found - "
			"skipping some tests: %s", error);
		skip_dcrypt = TRUE;
	}
	key_cache = oauth2_validation_key_cache_init();
	/* write HMAC secret */
	hs_sign_key =buffer_create_dynamic(default_pool, 32);
	void *ptr = buffer_append_space_unsafe(hs_sign_key, 32);
	random_fill(ptr, 32);
	buffer_t *b64_key = t_base64_encode(0, (size_t)-1,
					    hs_sign_key->data, hs_sign_key->used);
	save_key("HS256", str_c(b64_key));
}

static void test_do_deinit(void)
{
	dict_deinit(&keys_dict);
	dict_driver_unregister(&dict_driver_file);
	oauth2_validation_key_cache_deinit(&key_cache);
	i_unlink(".keys");
	buffer_free(&hs_sign_key);
	dcrypt_deinitialize();
}

int main(void)
{
	static void (*test_functions[])(void) = {
		test_do_init,
		test_jwt_hs_token,
		test_jwt_bad_valid_token,
		test_jwt_broken_token,
		test_jwt_dates,
		test_jwt_key_files,
		test_jwt_rs_token,
		test_jwt_ps_token,
		test_jwt_ec_token,
		test_do_deinit,
		NULL
	};
	int ret;
	ret = test_run(test_functions);
	return ret;
}

