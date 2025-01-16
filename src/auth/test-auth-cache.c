/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "auth-request.h"
#include "auth-cache.h"
#include "test-common.h"

const struct var_expand_table
auth_request_var_expand_static_tab[AUTH_REQUEST_VAR_TAB_COUNT + 1] = {
	{ .key = "user", .value = NULL },

	{ .key = "a", .value = NULL },
	{ .key = "b", .value = NULL },
	{ .key = "c", .value = NULL },
	VAR_EXPAND_TABLE_END
};

struct event *auth_event;

struct var_expand_table *
auth_request_get_var_expand_table_full(const struct auth_request *auth_request ATTR_UNUSED,
				       const char *username ATTR_UNUSED,
				       unsigned int *count ATTR_UNUSED)
{
	i_unreached();
}

static int mock_get_passdb(const char *key, const char **value_r,
			   void *context ATTR_UNUSED, const char **error_r)
{
	if (strcmp(key, "pfield") == 0) {
		*value_r = "pvalue";
		return 0;
	}
	*error_r = "No such key";
	return -1;
}

static int mock_get_userdb(const char *key, const char **value_r,
			   void *context ATTR_UNUSED, const char **error_r)
{
	if (strcmp(key, "ufield") == 0) {
		*value_r = "uvalue";
		return 0;
	}
	*error_r = "No such key";
	return -1;
}

int auth_request_var_expand_with_table(string_t *dest, const char *str,
				       const struct auth_request *auth_request,
				       const struct var_expand_table *table ATTR_UNUSED,
				       auth_request_escape_func_t *escape_func ATTR_UNUSED,
				       const char **error_r ATTR_UNUSED)
{
	const struct var_expand_params params = {
		.table = auth_request_var_expand_static_tab,
		.providers = (const struct var_expand_provider[]) {
			{ .key = "passdb", .func = mock_get_passdb },
			{ .key = "userdb", .func = mock_get_userdb },
			VAR_EXPAND_TABLE_END
		},
		.event = auth_request->event,
	};
	return var_expand(dest, str, &params, error_r);
}

static void test_auth_cache_parse_key(void)
{
	static const struct {
		const char *in, *out;
	} tests[] = {
		{ "%{user|username}", "%{user}" },
		{ "%{user|domain}", "%{user}" },
		{ "%{a}%{b}%{user}", "%{user}\t%{a}\t%{b}" },

		{ "foo%{a | substr(5, 5) }bar", "%{a}" },
		{ "foo%{b | substr(5, 5) }bar", "%{b}" },
		{ "foo%{c | substr(5, 5) }bar", "%{c}" },
		{ "%{a}%{b}", "%{a}\t%{b}" },
		/* test that passdb/userdb works */
		{
			"%{a}%{passdb:pfield}%{userdb:ufield}",
			"%{a}\t%{passdb:pfield}\t%{userdb:ufield}"
		},
		/* test that other providers are dropped */
		{ "%{a}%{provider:user}", "%{a}" },
	};
	const char *cache_key;
	unsigned int i;

	test_begin("auth cache parse key");

	for (i = 0; i < N_ELEMENTS(tests); i++) {
		cache_key = auth_cache_parse_key(pool_datastack_create(),
						 tests[i].in);
		test_assert_strcmp_idx(cache_key, tests[i].out, i);
	}
	test_end();
}

int main(void)
{
	lib_init();
	auth_event = event_create(NULL);
	static void (*const test_functions[])(void) = {
		test_auth_cache_parse_key,
		NULL
	};
	int ret = test_run(test_functions);
	event_unref(&auth_event);
	return ret;
}
