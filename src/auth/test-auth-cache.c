/* Copyright (c) Dovecot authors, see top-level COPYING file */

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

/* Username that cache keys are expanded with, or NULL to use the static
   table */
static const char *mock_user;

struct var_expand_table *
auth_request_get_var_expand_table_full(const struct auth_request *auth_request ATTR_UNUSED,
				       const char *username ATTR_UNUSED,
				       unsigned int *count)
{
	*count = 0;
	return NULL;
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
	if (mock_user != NULL) {
		str_printfa(dest, "P1\t%s", mock_user);
		return 0;
	}
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
	const char *cache_key, *error;
	unsigned int i;

	test_begin("auth cache parse key");

	for (i = 0; i < N_ELEMENTS(tests); i++) {
		test_assert_idx(auth_cache_parse_key_and_fields(
			pool_datastack_create(), tests[i].in, NULL, NULL,
			&cache_key, &error) == 0, i);
		test_assert_strcmp_idx(cache_key, tests[i].out, i);
	}

	test_end();
}

static void test_auth_cache_parse_key_errors(void)
{
	static const struct {
		const char *in, *out;
	} tests_bad[] = {
		{ "%u", "auth-cache: %u: Cache key must contain at least one variable" },
		{ "foobar", "auth-cache: foobar: Cache key must contain at least one variable" },
		{ "%{test", "auth-cache: var_expand_program_create(%{test) " \
			    "failed: syntax error, unexpected " },
	};
	const char *cache_key, *error;
	unsigned int i;

	test_begin("auth cache parse key errors");

	for (i = 0; i < N_ELEMENTS(tests_bad); i++) {
		test_assert_idx(auth_cache_parse_key_and_fields(
			pool_datastack_create(), tests_bad[i].in, NULL, NULL,
			&cache_key, &error) < 0, i);
		const char *expected = tests_bad[i].out;
		/* Bison uses different error on different versions */
		if (strstr(error, "$end") != NULL) {
			expected = t_strconcat(expected,
					"$end, expecting CCBRACE or PIPE", NULL);
		} else if (strstr(error, "end of file") != NULL) {
			expected = t_strconcat(expected,
					"end of file, expecting CCBRACE or PIPE",
					NULL);
		}
		test_assert_strcmp_idx(error, expected, i);
	}

	test_end();
}

static void test_auth_cache_insert_oversized(void)
{
	const size_t max_size = 1024;
	struct auth_cache_status status;
	struct auth_cache *cache;
	struct auth_request *request;
	const char *value;
	bool expired, neg_expired;
	unsigned int i;

	test_begin("auth cache insert oversized");

	request = i_new(struct auth_request, 1);
	request->event = event_create(auth_event);
	i_array_init(&request->authdb_event, 2);
	cache = auth_cache_new(max_size, 3600, 3600);

	T_BEGIN {
		string_t *big_user = t_str_new(max_size * 4);
		for (i = 0; i < max_size * 4; i++)
			str_append_c(big_user, 'A');
		mock_user = str_c(big_user);
		auth_cache_insert(cache, request, "%{user}", "x", TRUE);
		auth_cache_get_status(cache, &status);
		test_assert(status.used_size == 0);
		test_assert(auth_cache_lookup(cache, request, "%{user}", NULL,
					      &expired, &neg_expired) == NULL);
		mock_user = NULL;
	} T_END;

	for (i = 0; i < 200; i++) {
		T_BEGIN {
			mock_user = t_strdup_printf("user%04u", i);
			auth_cache_insert(cache, request, "%{user}", "pw", TRUE);
			mock_user = NULL;
		} T_END;
	}
	auth_cache_get_status(cache, &status);
	test_assert(status.used_size > 0);
	test_assert(status.used_size <= max_size);

	mock_user = "user0199";
	value = auth_cache_lookup(cache, request, "%{user}", NULL,
				  &expired, &neg_expired);
	test_assert_strcmp(value, "pw");

	/* Inserting an oversized value drops the existing entry of the
	   same key. */
	T_BEGIN {
		string_t *big_value = t_str_new(max_size * 4);
		for (i = 0; i < max_size * 4; i++)
			str_append_c(big_value, 'A');
		auth_cache_insert(cache, request, "%{user}", str_c(big_value),
				  TRUE);
	} T_END;
	test_assert(auth_cache_lookup(cache, request, "%{user}", NULL,
				      &expired, &neg_expired) == NULL);
	auth_cache_get_status(cache, &status);
	test_assert(status.used_size <= max_size);

	mock_user = NULL;
	auth_cache_free(&cache);
	array_free(&request->authdb_event);
	event_unref(&request->event);
	i_free(request);
	test_end();
}

int main(void)
{
	lib_init();
	auth_event = event_create(NULL);
	static void (*const test_functions[])(void) = {
		test_auth_cache_parse_key,
		test_auth_cache_parse_key_errors,
		test_auth_cache_insert_oversized,
		NULL
	};

	int ret = test_run(test_functions);

	event_unref(&auth_event);
	return ret;
}
