/* Copyright (c) Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "str.h"
#include "strescape.h"
#include "auth-secrets.h"

static void test_auth_field_secrets(void)
{
	static const struct {
		const char *field;
		const char *hidden;
	} tests[] = {
		{ "password=x", "password=<hidden>" },
		{ "proxy_pass=s3cret", "proxy_pass=<hidden>" },
		{ "userdb_private_password=", "userdb_private_password=<hidden>" },
		{ "pass=a=b", "pass=<hidden>" },
		{ "userPassword=x", "userPassword=<hidden>" },
		{ "PASS=x", "PASS=<hidden>" },
		{ "OldPassword=x", "OldPassword=<hidden>" },
		{ "passphrase=x", "passphrase=<hidden>" },
		{ "userPwd=x", "userPwd=<hidden>" },
		{ "client_secret=x", "client_secret=<hidden>" },
		{ "nonce=x", "nonce=<hidden>" },
		{ "password_hash=x", "password_hash=<hidden>" },
		{ "mail_crypt_private_key=x", "mail_crypt_private_key=<hidden>" },
		{ "KEY=x", "KEY=<hidden>" },
		{ "userHash=x", "userHash=<hidden>" },
		{ "ssl_server_key_file=/etc/key.pem",
		  "ssl_server_key_file=<hidden>" },
		{ "crypt_global_private_key/main/crypt_private_key_file=inline:x",
		  "crypt_global_private_key/main/crypt_private_key_file=<hidden>" },
		{ "auth_token=0123abcd", "auth_token=<hidden>" },
		{ "Auth_Token=0123abcd", "Auth_Token=<hidden>" },
		{ "auth_token=", "auth_token=<hidden>" },
		{ "access_token=abc", "access_token=<hidden>" },
		{ "Access_Token=abc", "Access_Token=<hidden>" },
		{ "token=abc", "token=<hidden>" },
		{ "TOKEN=abc", "TOKEN=<hidden>" },
		{ "from_pdb_access_token=abc", "from_pdb_access_token=<hidden>" },
		{ "x_auth_token=1", "x_auth_token=<hidden>" },
		{ "x_token=1", "x_token=<hidden>" },
		{ "auth_token_x=1", NULL },
		{ "token_type=Bearer", NULL },
		{ "access_token_x=1", NULL },
		{ "tokenizer=1", NULL },
		{ "user=passenger", NULL },
		{ "home=/home/user", NULL },
		{ "keyboard=us", NULL },
		{ "key_id=1", NULL },
		{ "ke=y", NULL },
		{ "x=monkey", NULL },
		{ "ssl_server_cert_file=/etc/cert.pem", NULL },
		{ "quota=a=pass", NULL },
		{ "user=PASSENGER", NULL },
		{ "quota=PASS", NULL },
		{ "pass", NULL },
		{ "auth_token", NULL },
		{ "token", NULL },
		{ "", NULL },
	};

	test_begin("auth_field_is_secret");
	for (unsigned int i = 0; i < N_ELEMENTS(tests); i++) {
		test_assert_idx(auth_field_is_secret(tests[i].field) ==
				(tests[i].hidden != NULL), i);
		test_assert_strcmp_idx(auth_field_hide_secret(tests[i].field),
				       tests[i].hidden != NULL ?
				       tests[i].hidden : tests[i].field, i);
	}
	test_end();
}

static void test_auth_field_key_secrets(void)
{
	static const struct {
		const char *key;
		bool secret;
	} tests[] = {
		{ "imapc_password", TRUE },
		{ "userPassword", TRUE },
		{ "OldPassword", TRUE },
		{ "passphrase", TRUE },
		{ "proxy_pass", TRUE },
		{ "userPwd", TRUE },
		{ "client_secret", TRUE },
		{ "nonce", TRUE },
		{ "password_hash", TRUE },
		{ "mail_crypt_private_key", TRUE },
		{ "key", TRUE },
		{ "nt_hash", TRUE },
		{ "ssl_client_key_file", TRUE },
		{ "crypt_private_key_file", TRUE },
		{ "auth_token", TRUE },
		{ "AUTH_TOKEN", TRUE },
		{ "access_token", TRUE },
		{ "Access_Token", TRUE },
		{ "token", TRUE },
		{ "TOKEN", TRUE },
		{ "from_pdb_access_token", TRUE },
		{ "x_auth_token", TRUE },
		{ "x_token", TRUE },
		{ "auth_token_x", FALSE },
		{ "token_type", FALSE },
		{ "access_token_x", FALSE },
		{ "tokenizer", FALSE },
		{ "user", FALSE },
		{ "quota", FALSE },
		{ "home", FALSE },
		{ "keyboard", FALSE },
		{ "ke", FALSE },
		{ "ssl_server_cert_file", FALSE },
		{ "", FALSE },
	};

	test_begin("auth_field_key_is_secret");
	for (unsigned int i = 0; i < N_ELEMENTS(tests); i++) {
		test_assert_idx(auth_field_key_is_secret(tests[i].key) ==
				tests[i].secret, i);
	}
	test_end();
}

static void test_auth_field_line_hide_secrets(void)
{
	string_t *line = t_str_new(256);
	string_t *expected = t_str_new(256);

	test_begin("auth_field_line_hide_secrets");
	str_append(line, "user@example.com\tsession=abc\tauth_token=0123abcd");
	str_append(line, "\tuserdb_fields=");
	str_append_tabescaped(line, "auth_user=u\tproxy_pass=s3cret\t"
			      "auth_token=0123abcd\tquota=1\\t2\tpassword=x");
	str_append(line, "\tstate=YWJj\tsession_pid=1234");

	str_append(expected, "user@example.com\tsession=abc"
		   "\tauth_token=<hidden>\tuserdb_fields=");
	str_append_tabescaped(expected, "auth_user=u\tproxy_pass=<hidden>\t"
			      "auth_token=<hidden>\tquota=1\\t2\t"
			      "password=<hidden>");
	str_append(expected, "\tstate=YWJj\tsession_pid=1234");

	test_assert_strcmp(auth_field_line_hide_secrets(str_c(line)),
			   str_c(expected));
	test_assert_strcmp(auth_field_line_hide_secrets("a\tb=c"), "a\tb=c");
	test_assert_strcmp(auth_field_line_hide_secrets(""), "");
	test_assert_strcmp(auth_field_line_hide_secrets(
		"<hidden>\tproxy_pass=x\tnopassword="),
		"<hidden>\tproxy_pass=<hidden>\tnopassword=<hidden>");

	str_truncate(line, 0);
	str_append(line, "user@example.com\t");
	str_append_tabescaped(line, "note=a\tb\\c");
	test_assert_strcmp(auth_field_line_hide_secrets(str_c(line)),
			   str_c(line));
	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_auth_field_secrets,
		test_auth_field_key_secrets,
		test_auth_field_line_hide_secrets,
		NULL
	};
	return test_run(test_functions);
}
