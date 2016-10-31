/* Copyright (c) 2015-2016 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "auth.h"
#include "passdb.h"
#include "userdb.h"
#include "auth-request.h"
#include "test-common.h"

static struct passdb_module test_passdb = {
	.id = 40
};
static struct userdb_module test_userdb = {
	.id = 41
};

static struct auth_passdb test_auth_passdb = {
	.passdb = &test_passdb
};
static struct auth_userdb test_auth_userdb = {
	.userdb = &test_userdb
};

static struct auth_request default_test_request = {
	.user = "-user@+domain1@+domain2",
	.service = "-service",

	.local_ip = { .family = AF_INET },
	.remote_ip = { .family = AF_INET },
	.client_pid = 54321,
	.mech_password = "-password",
	.mech_name = "-mech",
	.secured = TRUE,
	.local_port = 21,
	.remote_port = 210,
	.valid_client_cert = TRUE,

	.requested_login_user = "-loginuser@+logindomain1@+logindomain2",
	.session_id = "-session",
	.real_local_ip = { .family = AF_INET },
	.real_remote_ip = { .family = AF_INET },
	.real_local_port = 200,
	.real_remote_port = 201,
	.master_user = "-masteruser@-masterdomain1@-masterdomain2",
	.session_pid = 5000,
	.original_username = "-origuser@-origdomain1@-origdomain2",

	.passdb = &test_auth_passdb,
	.userdb = &test_auth_userdb
};

static struct auth_request test_request;
static struct auth_request empty_test_request = { .user = "" };

static const char *
test_escape(const char *string, const struct auth_request *request)
{
	char *dest;
	unsigned int i;

	test_assert(request == &test_request);

	dest = t_strdup_noconst(string);
	for (i = 0; dest[i] != '\0'; i++) {
		if (dest[i] == '-')
			dest[i] = '+';
	}
	return dest;
}

static bool test_empty_request(string_t *str, const char *input)
{
	const struct var_expand_table *tab =
		auth_request_get_var_expand_table(&empty_test_request, NULL);
	const char *error;

	str_truncate(str, 0);
	test_assert(var_expand(str, input, tab, &error) == 1);
	return strspn(str_c(str), "\n0") == str_len(str);
}

static void test_auth_request_var_expand_shortlong(void)
{
	static const char *test_input_short =
		"%u\n%n\n%d\n%s\n%h\n%l\n%r\n%p\n%w\n%m\n%c\n%a\n%b\n%k\n";
	static const char *test_input_long =
		"%{user}\n%{username}\n%{domain}\n%{service}\n%{home}\n"
		"%{lip}\n%{rip}\n%{pid}\n%{password}\n%{mech}\n%{secured}\n"
		"%{lport}\n%{rport}\n%{cert}\n";
	static const char *test_output =
		/* %{home} is intentionally always expanding to empty */
		"+user@+domain1@+domain2\n+user\n+domain1@+domain2\n+service\n\n"
		"7.91.205.21\n73.150.2.210\n54321\n+password\n+mech\nsecured\n"
		"21\n210\nvalid\n";
	const struct var_expand_table *tab;
	string_t *str = t_str_new(256);
	const char *error;

	test_begin("auth request var expand short and long");

	tab = auth_request_get_var_expand_table(&test_request, test_escape);
	test_assert(var_expand(str, test_input_short, tab, &error) == 1);
	test_assert(strcmp(str_c(str), test_output) == 0);

	str_truncate(str, 0);
	test_assert(var_expand(str, test_input_long, tab, &error) == 1);
	test_assert(strcmp(str_c(str), test_output) == 0);

	/* test with empty input that it won't crash */
	test_assert(test_empty_request(str, test_input_short));
	test_assert(test_empty_request(str, test_input_long));

	test_end();
}

static void test_auth_request_var_expand_flags(void)
{
	static const char *test_input = "%!\n%{secured}\n%{cert}\n";
	string_t *str = t_str_new(10);
	const char *error;

	test_begin("auth request var expand flags");

	test_request.userdb_lookup = FALSE;
	test_request.secured = FALSE;
	test_request.valid_client_cert = FALSE;
	test_assert(var_expand(str, test_input,
		auth_request_get_var_expand_table(&test_request, test_escape),
		&error) == 1);
	test_assert(strcmp(str_c(str), "40\n\n\n") == 0);

	test_request.userdb_lookup = TRUE;
	test_request.secured = TRUE;
	test_request.valid_client_cert = TRUE;

	str_truncate(str, 0);
	test_assert(var_expand(str, test_input,
		auth_request_get_var_expand_table(&test_request, test_escape),
		&error) == 1);
	test_assert(strcmp(str_c(str), "41\nsecured\nvalid\n") == 0);

	test_assert(test_empty_request(str, test_input));
	test_end();
}

static void test_auth_request_var_expand_long(void)
{
	static const char *test_input =
		"%{login_user}\n%{login_username}\n%{login_domain}\n%{session}\n"
		"%{real_lip}\n%{real_rip}\n%{real_lport}\n%{real_rport}\n"
		"%{master_user}\n%{session_pid}\n"
		"%{orig_user}\n%{orig_username}\n%{orig_domain}\n";
	static const char *test_output =
		"+loginuser@+logindomain1@+logindomain2\n+loginuser\n+logindomain1@+logindomain2\n+session\n"
		"13.81.174.20\n13.81.174.21\n200\n201\n"
		"+masteruser@+masterdomain1@+masterdomain2\n5000\n"
		"+origuser@+origdomain1@+origdomain2\n+origuser\n+origdomain1@+origdomain2\n";
	string_t *str = t_str_new(256);
	const char *error;

	test_begin("auth request var expand long-only");

	test_assert(var_expand(str, test_input,
		auth_request_get_var_expand_table(&test_request, test_escape),
		&error) == 1);
	test_assert(strcmp(str_c(str), test_output) == 0);

	test_assert(test_empty_request(str, test_input));
	test_end();
}

static void test_auth_request_var_expand_usernames(void)
{
	static const struct {
		const char *username, *output;
	} tests[] = {
		{ "-foo", "+foo\n\n\n\n+foo" },
		{ "-foo@-domain", "+foo\n+domain\n+domain\n+domain\n+foo@+domain" },
		{ "-foo@-domain1@-domain2", "+foo\n+domain1@+domain2\n+domain1\n+domain2\n+foo@+domain1@+domain2" }
	};
	static const char *test_input =
		"%{username}\n%{domain}\n%{domain_first}\n%{domain_last}\n%{user}";
	string_t *str = t_str_new(64);
	const char *error;
	unsigned int i;

	test_begin("auth request var expand usernames");
	for (i = 0; i < N_ELEMENTS(tests); i++) {
		test_request.user = t_strdup_noconst(tests[i].username);
		str_truncate(str, 0);
		test_assert(var_expand(str, test_input,
			auth_request_get_var_expand_table(&test_request, test_escape),
			&error) == 1);
		test_assert_idx(strcmp(str_c(str), tests[i].output) == 0, i);
	}
	test_request.user = default_test_request.user;
	test_end();
}

static void test_auth_request_var_expand_funcs(void)
{
	pool_t pool;
	const char *value, *error;

	test_begin("auth request var expand funcs");

	pool = pool_alloconly_create("test var expand funcs", 1024);
	test_request.extra_fields = auth_fields_init(pool);
	test_request.userdb_reply = auth_fields_init(pool);

	auth_fields_add(test_request.extra_fields, "pkey1", "-pval1", 0);
	auth_fields_add(test_request.extra_fields, "pkey2", "", 0);

	auth_fields_add(test_request.userdb_reply, "ukey1", "-uval1", 0);
	auth_fields_add(test_request.userdb_reply, "ukey2", "", 0);

	test_assert(t_auth_request_var_expand(
			"%{passdb:pkey1}\n%{passdb:pkey1:default1}\n"
			"%{passdb:pkey2}\n%{passdb:pkey2:default2}\n"
			"%{passdb:pkey3}\n%{passdb:pkey3:default3}\n"
			"%{passdb:ukey1}\n%{passdb:ukey1:default4}\n",
			&test_request, test_escape, &value, &error) == 0);
	test_assert(strcmp(value, "+pval1\n+pval1\n\n\n\ndefault3\n\ndefault4\n") == 0);

	test_assert(t_auth_request_var_expand(
			"%{userdb:ukey1}\n%{userdb:ukey1:default1}\n"
			"%{userdb:ukey2}\n%{userdb:ukey2:default2}\n"
			"%{userdb:ukey3}\n%{userdb:ukey3:default3}\n"
			"%{userdb:pkey1}\n%{userdb:pkey1:default4}\n",
			&test_request, test_escape, &value, &error) == 0);
	test_assert(strcmp(value, "+uval1\n+uval1\n\n\n\ndefault3\n\ndefault4\n") == 0);

	pool_unref(&pool);
	test_end();
}

int main(void)
{
	static void (*test_functions[])(void) = {
		test_auth_request_var_expand_shortlong,
		test_auth_request_var_expand_flags,
		test_auth_request_var_expand_long,
		test_auth_request_var_expand_usernames,
		test_auth_request_var_expand_funcs,
		NULL
	};

	default_test_request.local_ip.u.ip4.s_addr = htonl(123456789);
	default_test_request.remote_ip.u.ip4.s_addr = htonl(1234567890);
	default_test_request.real_local_ip.u.ip4.s_addr = htonl(223456788);
	default_test_request.real_remote_ip.u.ip4.s_addr = htonl(223456789);

	test_request = default_test_request;
	return test_run(test_functions);
}
