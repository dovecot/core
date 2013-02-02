/* Copyright (c) 2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "auth-request.h"
#include "auth-cache.h"
#include "test-common.h"

const struct var_expand_table auth_request_var_expand_static_tab[] = {
	/* these 3 must be in this order */
	{ 'u', NULL, "user" },
	{ 'n', NULL, "username" },
	{ 'd', NULL, "domain" },

	{ 'a', NULL, NULL },
	{ '\0', NULL, "longb" },
	{ 'c', NULL, "longc" },
	{ '\0', NULL, NULL }
};

const struct var_expand_table *
auth_request_get_var_expand_table(const struct auth_request *auth_request ATTR_UNUSED,
				  auth_request_escape_func_t *escape_func ATTR_UNUSED)
{
	return auth_request_var_expand_static_tab;
}

static void test_auth_cache_parse_key(void)
{
	struct {
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
	static void (*test_functions[])(void) = {
		test_auth_cache_parse_key,
		NULL
	};
	return test_run(test_functions);
}
