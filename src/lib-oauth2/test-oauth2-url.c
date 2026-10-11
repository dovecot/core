/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "str.h"
#include "env-util.h"
#include "http-url.h"
#include "var-expand.h"
#include "oauth2.h"
#include "test-common.h"

static void
test_oauth2_url_template_expand_one(const char *template_str,
				    const char *token, const char *expected)
{
	struct var_expand_program *prog;
	const char *error;

	test_assert(var_expand_program_create(template_str, &prog, &error) == 0);

	string_t *dest = t_str_new(64);
	test_assert(oauth2_url_template_expand(prog, token, dest, &error) == 0);
	test_assert_strcmp(str_c(dest), expected);

	var_expand_program_free(&prog);
}

static void
test_oauth2_url_template_expand_fail(const char *template_str,
				     const char *token, const char *expected)
{
	struct var_expand_program *prog;
	const char *error;

	test_assert(var_expand_program_create(template_str, &prog, &error) == 0);

	string_t *dest = t_str_new(64);
	test_assert(oauth2_url_template_expand(prog, token, dest, &error) == -1);
	test_assert_strcmp(error, expected);
	test_assert_cmp(str_len(dest), ==, 0);

	var_expand_program_free(&prog);
}

static void test_oauth2_url_template_expand_query_escape(void)
{
	test_begin("oauth2_url_template_expand(query escape)");
	test_oauth2_url_template_expand_one(
		"http://h/t?access_token=%{access_token}",
		"a&b#c%d/e?f=g+h",
		"http://h/t?access_token=a%26b%23c%25d%2fe%3ff%3dg%2bh");
	test_end();
}

static void test_oauth2_url_template_expand_path(void)
{
	struct var_expand_program *prog;
	struct http_url *url;
	const char *error;

	test_begin("oauth2_url_template_expand(path)");

	test_assert(var_expand_program_create("http://h/t/%{access_token}",
					      &prog, &error) == 0);

	string_t *dest = t_str_new(64);
	test_assert(oauth2_url_template_expand(prog, "x/y", dest, &error) == 0);
	test_assert_strcmp(str_c(dest), "http://h/t/x%2fy");

	/* the escaped slash must still be there once this goes through the
	   same URL parsing and target construction used to issue the
	   request - %2f must not turn back into a path separator. */
	test_assert(http_url_parse(str_c(dest), NULL, 0,
				   pool_datastack_create(), &url,
				   &error) == 0);
	test_assert_strcmp(http_url_create_target(url), "/t/x%2fy");

	var_expand_program_free(&prog);
	test_end();
}

static void test_oauth2_url_template_expand_env_escaped(void)
{
	test_begin("oauth2_url_template_expand(env provider escaped)");

	env_put("OAUTH2_TEST_S", "a&b=c");
	test_oauth2_url_template_expand_one(
		"https://idp/t?t=%{access_token}&s=%{env:OAUTH2_TEST_S}",
		"tok", "https://idp/t?t=tok&s=a%26b%3dc");
	test_oauth2_url_template_expand_one(
		"https://idp/t?t=%{access_token}&s=%{env:OAUTH2_TEST_S|safe}",
		"tok", "https://idp/t?t=tok&s=a&b=c");
	env_remove("OAUTH2_TEST_S");

	test_end();
}

static void test_oauth2_url_template_expand_token_chars(void)
{
	test_begin("oauth2_url_template_expand(token characters)");
	test_oauth2_url_template_expand_one(
		"https://idp/t?t=%{access_token}", "a:b@c",
		"https://idp/t?t=a%3ab%40c");
	test_oauth2_url_template_expand_one(
		"https://idp/t?t=%{access_token}", "-._~Az09",
		"https://idp/t?t=-._~Az09");
	test_oauth2_url_template_expand_one(
		"https://idp/t?t=%{access_token}", "", "https://idp/t?t=");
	test_oauth2_url_template_expand_one(
		"https://idp/t?t=%{access_token|safe}", "a&b",
		"https://idp/t?t=a&b");
	test_end();
}

static void test_oauth2_url_template_expand_filter_raw(void)
{
	test_begin("oauth2_url_template_expand(filters see the raw token)");
	test_oauth2_url_template_expand_one(
		"https://idp/t?h=%{access_token|sha256}", "a/b+c",
		"https://idp/t?h="
		"409922cc75a93c881693de9b625ae5099aab02c9925db0691f07f94ee9b67aa3");
	test_end();
}

static void test_oauth2_url_template_expand_env_base(void)
{
	test_begin("oauth2_url_template_expand(env base url)");

	env_put("OAUTH2_TEST_IDP", "http://idp:8080");
	test_oauth2_url_template_expand_one(
		"%{env:OAUTH2_TEST_IDP|safe}/tokeninfo?t=%{access_token}",
		"TOKEN", "http://idp:8080/tokeninfo?t=TOKEN");
	/* without safe the "://" is escaped and the token ends up
	   before any scheme://authority/ */
	test_oauth2_url_template_expand_fail(
		"%{env:OAUTH2_TEST_IDP}/tokeninfo?t=%{access_token}", "TOKEN",
		"%{access_token} must be in the URL path or query");
	env_remove("OAUTH2_TEST_IDP");

	test_end();
}

static void test_oauth2_url_template_expand_placement(void)
{
	test_begin("oauth2_url_template_expand(token placement)");

	env_put("OAUTH2_TEST_X", "http:/");
	test_oauth2_url_template_expand_fail(
		"%{env:OAUTH2_TEST_X|safe}/%{access_token}", "TOKEN",
		"%{access_token} must be in the URL path or query");
	env_put("OAUTH2_TEST_X", "http://idp");
	test_oauth2_url_template_expand_fail(
		"%{env:OAUTH2_TEST_X|safe}%{access_token}", "TOKEN",
		"%{access_token} must be in the URL path or query");
	/* empty authority: http:///TOKEN */
	env_put("OAUTH2_TEST_X", "http://");
	test_oauth2_url_template_expand_fail(
		"%{env:OAUTH2_TEST_X|safe}/%{access_token}", "TOKEN",
		"%{access_token} must be in the URL path or query");
	env_put("OAUTH2_TEST_X", "http://idp/");
	test_oauth2_url_template_expand_one(
		"%{env:OAUTH2_TEST_X|safe}%{access_token}", "TOKEN",
		"http://idp/TOKEN");
	env_remove("OAUTH2_TEST_X");

	test_oauth2_url_template_expand_fail(
		"http://idp#/%{access_token}", "TOKEN",
		"%{access_token} must be in the URL path or query");
	test_oauth2_url_template_expand_fail(
		"http://%{access_token}.idp/", "TOKEN",
		"%{access_token} must be in the URL path or query");

	test_end();
}

static void test_oauth2_url_template_expand_base(void)
{
	static const struct {
		const char *base;
		bool valid;
	} tests[] = {
		{ "http://idp/", TRUE },
		{ "http://idp?t=", TRUE },
		{ "HTTPS://idp.example.com/a/b?t=", TRUE },
		{ "http://user:pass@idp:8080/", TRUE },
		{ "http://127.0.0.1:8080/x?t=", TRUE },
		{ "http://[::1]/t?t=", TRUE },
		{ "http://[::1]:8080/", TRUE },
		/* no or malformed scheme */
		{ "idp/", FALSE },
		{ "/", FALSE },
		{ "1http://idp/", FALSE },
		{ "http:idp/", FALSE },
		{ "http:/idp/", FALSE },
		/* host */
		{ "http:///x?t=", FALSE },
		{ "http://user@/x?t=", FALSE },
		{ "http://:80/", FALSE },
		{ "http://my host/", FALSE },
		{ "http://./", FALSE },
		{ "http://-/", FALSE },
		{ "http://id%/", FALSE },
		{ "http://[::1/", FALSE },
		{ "http://[::1]x/", FALSE },
		{ "http://[]/", FALSE },
		/* port */
		{ "http://idp:99999/", FALSE },
		{ "http://idp:80x/", FALSE },
		/* the token must not land in the authority or fragment */
		{ "http://idp", FALSE },
		{ "http://idp:8080", FALSE },
		{ "http://idp#/", FALSE },
		{ "http://idp?a#", FALSE },
	};

	test_begin("oauth2_url_template_expand(base url)");

	for (unsigned int i = 0; i < N_ELEMENTS(tests); i++) {
		env_put("OAUTH2_TEST_X", tests[i].base);
		T_BEGIN {
			if (tests[i].valid) {
				test_oauth2_url_template_expand_one(
					"%{env:OAUTH2_TEST_X|safe}%{access_token}",
					"TOKEN", t_strconcat(tests[i].base,
							     "TOKEN", NULL));
			} else {
				test_oauth2_url_template_expand_fail(
					"%{env:OAUTH2_TEST_X|safe}%{access_token}",
					"TOKEN",
					"%{access_token} must be in the URL path or query");
			}
		} T_END;
	}
	env_remove("OAUTH2_TEST_X");

	test_end();
}

static void test_oauth2_url_template_expand_unknown_var(void)
{
	struct var_expand_program *prog;
	const char *error;

	test_begin("oauth2_url_template_expand(unknown variable)");

	test_assert(var_expand_program_create("http://h/%{user}?t=%{access_token}",
					      &prog, &error) == 0);

	string_t *dest = t_str_new(64);
	test_assert(oauth2_url_template_expand(prog, "tok", dest, &error) == -1);
	test_assert_strcmp(error, "Unknown variable 'user'");

	var_expand_program_free(&prog);
	test_end();
}

static void test_oauth2_url_template_expand_dot_segment(void)
{
	static const char *const dangerous_tokens[] = { ".", ".." };

	test_begin("oauth2_url_template_expand(dot segment token)");

	for (unsigned int i = 0; i < N_ELEMENTS(dangerous_tokens); i++) {
		test_oauth2_url_template_expand_fail(
			"http://h/t/%{access_token}", dangerous_tokens[i],
			"Invalid token");
	}
	/* the filter output is what ends up in the URL */
	test_oauth2_url_template_expand_fail(
		"http://h/t/%{access_token|substr(0,1)}", ".x",
		"Invalid token");
	test_oauth2_url_template_expand_fail(
		"http://h/t/%{access_token|substr(0,2)}", "..x",
		"Invalid token");

	test_end();
}

static void test_oauth2_url_template_expand_dots_inside(void)
{
	test_begin("oauth2_url_template_expand(dots inside token)");
	test_oauth2_url_template_expand_one("http://h/t/%{access_token}",
					    "a..b", "http://h/t/a..b");
	test_end();
}

static void test_oauth2_url_template_check(void)
{
	static const char *const placement =
		"%{access_token} must be in the URL path or query";
	static const struct {
		const char *input;
		const char *error;
	} tests[] = {
		{ "https://idp/t", NULL },
		{ "https://idp/t?t=%{access_token}", NULL },
		{ "https://idp/%{access_token}", NULL },
		{ "https://idp?t=%{access_token}", NULL },
		{ "https://idp/t?t=%{access_token|safe}", NULL },
		{ "%{env:IDP_URL|safe}/tokeninfo?t=%{access_token}", NULL },
		{ "http://idp:%{env:IDP_PORT|safe}/t?t=%{access_token}", NULL },
		{ "%{env:IDP_SCHEME|safe}://%{env:IDP_HOST|safe}/%{access_token}",
		  NULL },
		/* userinfo is escaped like path data */
		{ "http://%{env:U}:%{env:P}@idp/t?t=%{access_token}", NULL },
		{ "http://%{env:U}@%{env:H|safe}/t?t=%{access_token}", NULL },
		/* path and query data is escaped, no safe needed */
		{ "https://idp/%{env:P}/t?s=%{env:S}&t=%{access_token}", NULL },

		{ "http://%{access_token}.idp/", placement },
		{ "http://u:%{access_token}@idp/", placement },
		{ "http://idp:%{access_token}/", placement },
		{ "http://idp%{access_token}", placement },
		{ "%{env:X|safe}//%{access_token}/", placement },
		{ "%{env:X|safe}%{access_token}", placement },
		{ "%{access_token}", placement },
		{ "%{access_token|safe}/t", placement },
		{ "http://%{env:H}/%{access_token}",
		  "%{env:H} is part of the URL scheme or host and needs the "
		  "safe filter, use %{env:H|safe}" },
		{ "%{env:IDP_URL}/tokeninfo?t=%{access_token}",
		  "%{env:IDP_URL} is part of the URL scheme or host and needs the "
		  "safe filter, use %{env:IDP_URL|safe}" },
		{ "http://idp:%{env:PORT}/t",
		  "%{env:PORT} is part of the URL scheme or host and needs the "
		  "safe filter, use %{env:PORT|safe}" },
		{ "http://%{env:U}@%{env:H}/t",
		  "%{env:H} is part of the URL scheme or host and needs the "
		  "safe filter, use %{env:H|safe}" },
		/* the token in the fragment, with other variables present */
		{ "http://idp#/%{access_token}", placement },
		{ "http://%{env:H|safe}#/%{access_token}", placement },
		{ "https://idp/t?s=%{env:S}#%{access_token}", placement },
		{ "https://idp/t#%{access_token}", placement },
		{ "https://idp/t?s=%{env:S}#%{env:F}", NULL },
		/* IPv6 literal */
		{ "http://[::1]:%{env:P|safe}/t?t=%{access_token}", NULL },
		{ "http://[::1]:%{env:P}/t?t=%{access_token}",
		  "%{env:P} is part of the URL scheme or host and needs the "
		  "safe filter, use %{env:P|safe}" },
		/* the placement error wins */
		{ "http://%{env:H}.%{access_token}/", placement },
	};

	test_begin("oauth2_url_template_check");

	for (unsigned int i = 0; i < N_ELEMENTS(tests); i++) T_BEGIN {
		struct var_expand_program *prog;
		const char *error = NULL;

		test_assert_idx(var_expand_program_create(tests[i].input,
							  &prog, &error) == 0, i);
		int ret = oauth2_url_template_check(prog, &error);
		test_assert_idx((ret == 0) == (tests[i].error == NULL), i);
		if (tests[i].error != NULL)
			test_assert_strcmp_idx(error, tests[i].error, i);
		var_expand_program_free(&prog);
	} T_END;

	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_oauth2_url_template_expand_query_escape,
		test_oauth2_url_template_expand_path,
		test_oauth2_url_template_expand_env_escaped,
		test_oauth2_url_template_expand_token_chars,
		test_oauth2_url_template_expand_filter_raw,
		test_oauth2_url_template_expand_env_base,
		test_oauth2_url_template_expand_placement,
		test_oauth2_url_template_expand_base,
		test_oauth2_url_template_expand_unknown_var,
		test_oauth2_url_template_expand_dot_segment,
		test_oauth2_url_template_expand_dots_inside,
		test_oauth2_url_template_check,
		NULL
	};
	return test_run(test_functions);
}
