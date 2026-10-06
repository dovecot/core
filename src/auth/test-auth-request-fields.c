/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "test-auth.h"
#include "auth-common.h"
#include "str.h"
#include "strescape.h"
#include "auth-settings.h"
#include "auth-request.h"
#include "auth-fields.h"

struct test_auth_request_field {
	const char *internal_name;
	const char *event_field;
	const char *value;
};

static const struct test_auth_request_field auth_request_field_names[] = {
	/* use the order in auth_request_export() */
#define PREFIX "\t\r\n\001prefix-"
	{ "user", "user", PREFIX"testuser" },
	{ "protocol", "protocol", PREFIX"testprotocol" },
	{ "master-user", "master_user", PREFIX"testmasteruser" },
	{ "original-username", "original_user", PREFIX"testoriguser" },
	{ "requested-login-user", "login_user", PREFIX"testloginuser" },
	{ "lip", "local_ip", "255.254.253.252" },
	{ "rip", "remote_ip", "155.154.153.152" },
	{ "lport", "local_port", "12" },
	{ "rport", "remote_port", "13" },
	{ "real_lip", "real_local_ip", "1.2.3.4" },
	{ "real_rip", "real_remote_ip", "5.6.7.8" },
	{ "real_lport", "real_local_port", "14" },
	{ "real_rport", "real_remote_port", "15" },
	{ "local_name", "local_name", PREFIX"testlocalname" },
	{ "session", "session", PREFIX"testsession" },
	{ "secured", NULL, "" },
	{ "skip-password-check", NULL, "" },
	{ "delayed-credentials", NULL, "" },
	{ "valid-client-cert", NULL, "" },
	{ "no-penalty", NULL, "" },
	{ "successful", NULL, "" },
	{ "mech", "mechanism", "TOKEN" },
	{ "client_id", "client_id", PREFIX"testclientid" },
	{ "passdb_extrafield1", NULL, PREFIX"extravalue1" },
	{ "passdb_extrafield2", NULL, PREFIX"extravalue2" },
	{ "userdb_uextrafield1", NULL, PREFIX"userextravalue1" },
	{ "userdb_uextrafield2", NULL, PREFIX"userextravalue2" },
};

static struct auth_request *test_auth_request_init(void)
{
	struct auth_request *request;
	pool_t pool = pool_alloconly_create("test auth request", 1024);
	request = p_new(pool, struct auth_request, 1);
	request->pool = pool;
	request->event = event_create(NULL);
	request->set = global_auth_settings;
	request->refcount = 1;
	p_array_init(&request->authdb_event, pool, 1);
	auth_request_fields_alloc(request);
	auth_request_fields_init(request);

	/* fill out fields that are always exported */
	request->fields.user = "user";
	request->fields.original_username = "user";
	request->fields.protocol = "protocol";
	return request;
}

static void test_auth_request_deinit(struct auth_request *request)
{
	event_unref(&request->event);
	pool_unref(&request->pool);
}

static void test_auth_request_fields_list(void)
{
	struct auth_request *request = test_auth_request_init();
	string_t *exported = t_str_new(512);
	for (unsigned int i = 0; i < N_ELEMENTS(auth_request_field_names); i++) {
		const struct test_auth_request_field *test =
			&auth_request_field_names[i];
		test_assert_idx(auth_request_import(request,
			test->internal_name, test->value), i);

		str_append(exported, test->internal_name);
		if (test->value[0] != '\0') {
			str_append_c(exported, '=');
			str_append_tabescaped(exported, test->value);
		}
		str_append_c(exported, '\t');

		if (test->event_field != NULL) {
			const char *value =
				event_find_field_recursive_str(request->event, test->event_field);
			test_assert_idx(null_strcmp(value, test->value) == 0, i);
		}
	}
	str_truncate(exported, str_len(exported)-1);

	string_t *exported2 = t_str_new(512);
	auth_request_export(request, exported2);
	test_assert_strcmp(str_c(exported), str_c(exported2));

	test_auth_request_deinit(request);
}

static bool
test_auth_request_export_cmp(struct auth_request *request,
			     const char *key, const char *value)
{
	string_t *exported = t_str_new(128);
	str_append(exported, "user=user\tprotocol=protocol\toriginal-username=user\t");
	str_append(exported, key);
	if (value[0] != '\0') {
		str_append_c(exported, '=');
		str_append_tabescaped(exported, value);
	}

	string_t *exported2 = t_str_new(128);
	auth_request_export(request, exported2);
	test_assert_strcmp(str_c(exported), str_c(exported2));
	return strcmp(str_c(exported), str_c(exported2)) == 0;

}

static void test_auth_request_fields_secured(void)
{
	struct auth_request *request = test_auth_request_init();

	test_assert(auth_request_import(request, "secured", ""));
	test_assert(test_auth_request_export_cmp(request, "secured", ""));
	test_assert(null_strcmp(event_find_field_recursive_str(request->event, "transport"), "secured") == 0);

	test_assert(auth_request_import(request, "secured", "tls"));
	test_assert(test_auth_request_export_cmp(request, "secured", "tls"));
	test_assert(null_strcmp(event_find_field_recursive_str(request->event, "transport"), "TLS") == 0);

	test_assert(auth_request_import(request, "secured", "blah"));
	test_assert(test_auth_request_export_cmp(request, "secured", ""));
	test_assert(null_strcmp(event_find_field_recursive_str(request->event, "transport"), "secured") == 0);
	test_auth_request_deinit(request);
}

static void test_auth_request_export_import(void)
{
	struct auth_request *request_a = test_auth_request_init();
	string_t *exported_a = t_str_new(128);
	string_t *exported_b = t_str_new(128);
	request_a->passdb_success = TRUE;
	auth_request_set_field(request_a, "event_brand with fun = \" values",
			       "this = has _ fun \t values \"",
			       SASL_MECH_NAME_PLAIN);
	auth_request_export(request_a, exported_a);
	test_auth_request_deinit(request_a);

	/* then import it */
	struct auth_request *request_b = test_auth_request_init();
	const char *const *args = t_strsplit_tabescaped(str_c(exported_a));
	for (; *args != NULL; args++) {
		const char *value = strchr(*args, '=');
		if (value == NULL)
			(void)auth_request_import(request_b, *args, "");
		else {
			const char *key = t_strdup_until(*args, value++);
			(void)auth_request_import(request_b, key, value);
		}
	}
	auth_request_export(request_b, exported_b);
	test_auth_request_deinit(request_b);
	test_assert_strcmp(str_c(exported_a), str_c(exported_b));
}

static void test_auth_fields_invalid_key(void)
{
	pool_t pool = pool_alloconly_create("test auth fields", 256);
	struct auth_fields *fields = auth_fields_init(pool);

	const char *const args[] = {
		"a\033b=1", "a\tb=2", "=3", "del\177", "ok=a\033b", NULL
	};

	test_assert(auth_fields_key_is_valid("ok"));
	test_assert(!auth_fields_key_is_valid(""));
	test_assert(!auth_fields_key_is_valid("a\033b"));
	test_assert(!auth_fields_key_is_valid("a\tb"));
	test_assert(!auth_fields_key_is_valid("a\nb"));
	test_assert(!auth_fields_key_is_valid("del\177"));

	/* invalid keys are skipped and reported, valid ones still imported,
	   also with a control char in the value */
	test_assert(auth_fields_import_args(fields, args, 0) < 0);
	test_assert_strcmp(auth_fields_find(fields, "ok"), "a\033b");
	test_assert(auth_fields_find(fields, "a\033b") == NULL);
	test_assert(auth_fields_find(fields, "a\tb") == NULL);
	test_assert(auth_fields_find(fields, "del\177") == NULL);

	/* the prefix must not rescue an empty key */
	auth_fields_reset(fields);
	test_assert(auth_fields_import_prefixed(fields, "forward_", "=x", 0) < 0);
	test_assert(auth_fields_is_empty(fields));

	pool_unref(&pool);
}

/* Usernames are interpolated into filesystem paths, so a "/" or "@" delimited
   component consisting solely of dots must not be accepted. */
struct test_username_case {
	const char *username;
	bool accepted;
};

static struct auth_settings test_username_auth_set = {
	.master_user_separator = "",
	.default_domain = "",
	.username_format = "",
};

/* the check has to run on the expanded username, since auth_username_format
   can turn an accepted username into a traversing one */
static struct auth_settings test_username_format_auth_set = {
	.master_user_separator = "",
	.default_domain = "",
	.username_format = "%{user | username | truncate(2)}",
};

static void
test_auth_request_usernames(struct auth_settings *set,
			    const struct test_username_case *cases,
			    unsigned int count)
{
	/* allow all characters, so the "/" cases reach the dots check */
	memset(set->username_chars_map, 1, sizeof(set->username_chars_map));

	for (unsigned int i = 0; i < count; i++) {
		struct auth_request *request = test_auth_request_init();
		const char *error;

		request->set = set;
		test_assert_idx(auth_request_set_username(request,
			cases[i].username, &error) == cases[i].accepted, i);
		test_auth_request_deinit(request);
	}
}

static void test_auth_request_username_dots(void)
{
	static const struct test_username_case cases[] = {
		{ ".", FALSE },
		{ "..", FALSE },
		{ "...", FALSE },
		{ "..@example.com", FALSE },
		{ "user@..", FALSE },
		{ "a/../b", FALSE },
		{ "a/..", FALSE },
		{ "./a", FALSE },
		{ "../a", FALSE },
		{ "first.last@example.com", TRUE },
		{ "user..@example.com", TRUE },
		{ "..key@example.com", TRUE },
		{ "user..name@example.com", TRUE },
		{ "a/b", TRUE },
		{ "user@", TRUE },
	};
	/* truncate(2) leaves ".." and "ab" */
	static const struct test_username_case format_cases[] = {
		{ "..x@example.com", FALSE },
		{ "abc@example.com", TRUE },
	};

	test_auth_request_usernames(&test_username_auth_set,
				    cases, N_ELEMENTS(cases));
	test_auth_request_usernames(&test_username_format_auth_set,
				    format_cases, N_ELEMENTS(format_cases));
}

void test_auth_request_fields(void)
{
	test_begin("auth request fields");
	test_auth_request_fields_list();
	test_auth_request_fields_secured();
	test_auth_request_export_import();
	test_auth_fields_invalid_key();
	test_auth_request_username_dots();
	test_end();
}
