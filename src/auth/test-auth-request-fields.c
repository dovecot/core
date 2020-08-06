/* Copyright (c) 2020 Dovecot authors, see the included COPYING file */

#include "test-auth.h"
#include "str.h"
#include "strescape.h"
#include "auth-request.h"

struct test_auth_request_field {
	const char *internal_name;
	const char *event_field;
	const char *value;
};

static const struct test_auth_request_field auth_request_field_names[] = {
	/* use the order in auth_request_export() */
#define PREFIX "\t\r\n\001prefix-"
	{ "user", "user", PREFIX"testuser" },
	{ "service", "service", PREFIX"testservice" },
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

static struct auth_request *
test_auth_request_init(const struct mech_module *mech)
{
	struct auth_request *request;
	pool_t pool = pool_alloconly_create("test auth request", 1024);

	request = p_new(pool, struct auth_request, 1);
	request->pool = pool;
	request->event = event_create(NULL);
	request->mech = mech;
	auth_request_fields_init(request);

	/* fill out fields that are always exported */
	request->fields.user = "user";
	request->fields.original_username = "user";
	request->fields.service = "service";
	return request;
}

static void test_auth_request_deinit(struct auth_request *request)
{
	event_unref(&request->event);
	pool_unref(&request->pool);
}

static void test_auth_request_fields_list(void)
{
	struct auth_request *request =
		test_auth_request_init(&mech_dovecot_token);
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
				event_find_field_str(request->event, test->event_field);
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
	str_append(exported, "user=user\tservice=service\toriginal-username=user\t");
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
	struct auth_request *request = test_auth_request_init(NULL);

	test_assert(auth_request_import(request, "secured", ""));
	test_assert(test_auth_request_export_cmp(request, "secured", ""));
	test_assert(null_strcmp(event_find_field_str(request->event, "transport"), "trusted") == 0);

	test_assert(auth_request_import(request, "secured", "tls"));
	test_assert(test_auth_request_export_cmp(request, "secured", "tls"));
	test_assert(null_strcmp(event_find_field_str(request->event, "transport"), "TLS") == 0);

	test_assert(auth_request_import(request, "secured", "blah"));
	test_assert(test_auth_request_export_cmp(request, "secured", ""));
	test_assert(null_strcmp(event_find_field_str(request->event, "transport"), "trusted") == 0);
	test_auth_request_deinit(request);
}

void test_auth_request_fields(void)
{
	test_begin("auth request fields");
	test_auth_request_fields_list();
	test_auth_request_fields_secured();
	test_end();
}
