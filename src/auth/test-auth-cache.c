/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "auth-request.h"
#include "auth-cache.h"
#include "test-common.h"

const struct var_expand_table
auth_request_var_expand_static_tab[AUTH_REQUEST_VAR_TAB_COUNT + 1] = {
	/* these 3 must be in this order */
	{ 'u', NULL, "user" },
	{ 'n', NULL, "username" },
	{ 'd', NULL, "domain" },

	{ 'a', NULL, NULL },
	{ '\0', NULL, "longb" },
	{ 'c', NULL, "longc" },
	{ '\0', NULL, NULL }
};

struct event *auth_event;

struct var_expand_table *
auth_request_get_var_expand_table_full(const struct auth_request *auth_request ATTR_UNUSED,
				       const char *username ATTR_UNUSED,
				       auth_request_escape_func_t *escape_func ATTR_UNUSED,
				       unsigned int *count ATTR_UNUSED)
{
	i_unreached();
}

int auth_request_var_expand_with_table(string_t *dest, const char *str,
				       const struct auth_request *auth_request ATTR_UNUSED,
				       const struct var_expand_table *table ATTR_UNUSED,
				       auth_request_escape_func_t *escape_func ATTR_UNUSED,
				       const char **error_r ATTR_UNUSED)
{
	return var_expand(dest, str, auth_request_var_expand_static_tab, error_r);
}

static void test_auth_cache_parse_key(void)
{
	static const struct {
		const char *in, *out;
	} tests[] = {
		{ "%n@%d", "%u" },
		{ "%{username}@%{domain}", "%u" },
		{ "%n%d%u", "%u" },
		{ "%n", "%n" },
		{ "%d", "%d" },
		{ "%a%b%u", "%u\t%a\t%b" },

		{ "foo%5.5Mabar", "%a" },
		{ "foo%5.5M{longb}bar", "%{longb}" },
		{ "foo%5.5Mcbar", "%c" },
		{ "foo%5.5M{longc}bar", "%c" },
		{ "%a%b", "%a\t%b" },
		{ "%a%{longb}%a", "%a\t%{longb}" },
		{ "%{longc}%c", "%c" },
		{ "%c%a%{longc}%c", "%a\t%c" },
		{ "%a%{env:foo}%{env:foo}%a", "%a\t%{env:foo}\t%{env:foo}" }
	};
	const char *cache_key;
	unsigned int i;

	test_begin("auth cache parse key");

	for (i = 0; i < N_ELEMENTS(tests); i++) {
		cache_key = auth_cache_parse_key(pool_datastack_create(),
						 tests[i].in);
		test_assert(strcmp(cache_key, tests[i].out) == 0);
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
