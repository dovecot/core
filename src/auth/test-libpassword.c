/* Copyright (c) 2018 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "password-scheme.h"

#ifdef HAVE_LIBSODIUM
#include <sodium.h>
#endif

static struct {
	const char *scheme_generated;
	const char *scheme_detected;
} known_non_aliases[] = {
	{ "MD5", "DES-CRYPT" },
	{ "MD5-CRYPT", "DES-CRYPT" },
	{ "SKEY", "OTP" },
	{ "ARGON2ID", "ARGON2I" },
};

/* some algorithms are detected as something other, because they are compatible
   but not considered aliases by dovecot. treat those here to avoid false errors. */
static bool schemes_are_known_non_alias(const char *generated, const char *detected)
{
	for(size_t i = 0; i < N_ELEMENTS(known_non_aliases); i++) {
		if (strcmp(known_non_aliases[i].scheme_generated, generated) == 0 &&
		    strcmp(known_non_aliases[i].scheme_detected, detected) == 0)
			return TRUE;
	}
	return FALSE;
}

static void
test_password_scheme(const char *scheme, const char *crypted,
		     const char *plaintext)
{
	struct password_generate_params params = {
		.user = "testuser1",
		.rounds = 0,
	};
	const unsigned char *raw_password;
	size_t siz;
	const char *error, *scheme2;

	test_begin(t_strdup_printf("password scheme(%s)", scheme));

	test_assert(strcmp(password_get_scheme(&crypted), scheme) == 0);
	test_assert(password_decode(crypted, scheme, &raw_password, &siz, &error) == 1);
	test_assert(password_verify(plaintext, &params, scheme, raw_password, siz, &error) == 1);

	test_assert(password_generate_encoded(plaintext, &params, scheme, &crypted));
	crypted = t_strdup_printf("{%s}%s", scheme, crypted);
	test_assert(strcmp(password_get_scheme(&crypted), scheme) == 0);
	test_assert(password_decode(crypted, scheme, &raw_password, &siz, &error) == 1);
	test_assert(password_verify(plaintext, &params, scheme, raw_password, siz, &error) == 1);

	scheme2 = password_scheme_detect(plaintext, crypted, &params);

	test_assert(scheme2 != NULL &&
		    (password_scheme_is_alias(scheme, scheme2) ||
		     schemes_are_known_non_alias(scheme, scheme2)));

	test_end();
}

static void test_password_failures(void)
{
	const char *scheme = "PLAIN";
	const char *crypted = "{PLAIN}invalid";
	const char *plaintext = "test";

	struct password_generate_params params = {
		.user = "testuser1",
		.rounds = 0,
	};
	const unsigned char *raw_password;
	size_t siz;
	const char *error;

	test_begin("password scheme failures");

	/* wrong password */
	test_assert(strcmp(password_get_scheme(&crypted), scheme) == 0);
	test_assert(password_decode(crypted, scheme, &raw_password, &siz, &error) == 1);
	test_assert(password_verify(plaintext, &params, scheme, raw_password, siz, &error) == 0);

	/* unknown scheme */
	crypted = "{INVALID}invalid";
	scheme = password_get_scheme(&crypted);
	test_assert(password_decode(crypted, scheme, &raw_password, &siz, &error) == 0);

	/* crypt with empty value */
	test_assert(password_verify(plaintext, &params, "CRYPT", NULL, 0, &error) == 0);

	test_end();
}

static void test_password_schemes(void)
{
	test_password_scheme("PLAIN", "{PLAIN}test", "test");
	test_password_scheme("CRYPT", "{CRYPT}//EsnG9FLTKjo", "test");
	test_password_scheme("PLAIN-MD4", "{PLAIN-MD4}db346d691d7acc4dc2625db19f9e3f52", "test");
	test_password_scheme("MD5", "{MD5}$1$wmyrgRuV$kImF6.9MAFQNHe23kq5vI/", "test");
	test_password_scheme("SHA1", "{SHA1}qUqP5cyxm6YcTAhz05Hph5gvu9M=", "test");
	test_password_scheme("LANMAN", "{LANMAN}01fc5a6be7bc6929aad3b435b51404ee", "test");
	test_password_scheme("NTLM", "{NTLM}0cb6948805f797bf2a82807973b89537", "test");
	test_password_scheme("SMD5", "{SMD5}JTu1KRwptKZJg/RLd+6Vn5GUd0M=", "test");
	test_password_scheme("LDAP-MD5", "{LDAP-MD5}CY9rzUYh03PK3k6DJie09g==", "test");
	test_password_scheme("SHA256", "{SHA256}n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=", "test");
	test_password_scheme("SHA512", "{SHA512}7iaw3Ur350mqGo7jwQrpkj9hiYB3Lkc/iBml1JQODbJ6wYX4oOHV+E+IvIh/1nsUNzLDBMxfqa2Ob1f1ACio/w==", "test");
	test_password_scheme("SSHA", "{SSHA}H/zrDv8FXUu1JmwvVYijfrYEF34jVZcO", "test");
	test_password_scheme("MD5-CRYPT", "{MD5-CRYPT}$1$GgvxyNz8$OjZhLh4P.gF1lxYEbLZ3e/", "test");
	test_password_scheme("OTP", "{OTP}sha1 1024 ae6b49aa481f7233 f69fc7f98b8fbf54", "test");
	test_password_scheme("PBKDF2", "{PBKDF2}$1$bUnT4Pl7yFtYX0KU$5000$50a83cafdc517b9f46519415e53c6a858908680a", "test");
	test_password_scheme("RPA", "{RPA}f89cb77d46507afe985d80822b6b6c39", "test");
	test_password_scheme("SKEY", "{SKEY}md4 1024 ce20d20fae368ff2 689aea1b24ed6438", "test");
	test_password_scheme("CRAM-MD5", "{CRAM-MD5}e02d374fde0dc75a17a557039a3a5338c7743304777dccd376f332bee68d2cf6", "test");
	test_password_scheme("DIGEST-MD5", "{DIGEST-MD5}77c1a8c437c9b08ba2f460fe5d58db5d", "test");
	test_password_scheme("SCRAM-SHA-1", "{SCRAM-SHA-1}4096,GetyLXdBuHzf1FWf8SLz2Q==,NA/OqmF4hhrsrB9KR7po+dliTGM=,QBiURvQaE6H6qYTmeghDHLANBFQ=", "test");
	test_password_scheme("SCRAM-SHA-256", "{SCRAM-SHA-256}4096,LfNGSFqiFykEZ1xDAYlnKQ==,"
					       "HACNf9CII7cMz3XjRy/Oh3Ae2LHApoDyNw74d3YtFws=,"
					       "AQH0j7Hf8J12g8eNBadvzlNB2am3PxgNwFCFd3RxEaw=",
			     "test");
	test_password_scheme("BLF-CRYPT", "{BLF-CRYPT}$2y$05$11ipvo5dR6CwkzwmhwM26OXgzXwhV2PyPuLV.Qi31ILcRcThQpEiW", "test");
#ifdef HAVE_LIBSODIUM
	test_password_scheme("ARGON2I", "{ARGON2I}$argon2i$v=19$m=32768,t=4,p=1$f2iuP4aUeNMrgu34fhOkkg$1XSZZMWlIs0zmE+snlUIcLADO3GXbA2O/hsQmmc317k", "test");
#ifdef crypto_pwhash_ALG_ARGON2ID13
	test_password_scheme("ARGON2ID", "{ARGON2ID}$argon2id$v=19$m=65536,t=3,p=1$vBb99oJ12p3WAdYlaMHz1A$jtFOtbo/sYV9OSlTxDo/nVNq3uArHd5GJSEx0ty85Cc", "test");
#endif
#endif
}


int main(void)
{
	static void (*const test_functions[])(void) = {
		test_password_schemes,
		test_password_failures,
		NULL
	};
	password_schemes_init();
	return test_run(test_functions);
}
