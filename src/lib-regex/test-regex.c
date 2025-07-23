/* Copyright (C) 2025 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "test-common.h"
#include "array.h"
#include "str.h"
#include "dregex.h"

#ifdef HAVE_LIBPCRE

static const bool debug = FALSE;

struct test_case {
	const char *subject;
	const char *pattern;
	const char *replacement;
	const char *result;
	const char *error;
	enum dregex_flags flags;
	int compile_ret;
	int match_ret;
};

static void run_match_tests(const struct test_case *cases)
{
	unsigned int idx;
	struct dregex_code *code = dregex_code_create();

	for(idx = 0; cases[idx].pattern != NULL; idx++) {
		const char *error = NULL;
		const struct test_case *test = &cases[idx];

		if (debug) {
			i_debug("pattern = %s, subject = %s", test->pattern,
				test->subject);
		}

		/* compile pattern */
		int ret = dregex_code_compile(code, test->pattern, test->flags,
					     &error);
		test_assert_cmp_idx(test->compile_ret, ==, ret, idx);
		if (test->compile_ret < 0) {
			test_assert_strcmp_idx(test->error, error, idx);
			continue;
		} else if (ret < 0) {
			error = t_strdup_printf("Unexpected error: %s", error);
			test_assert_failed_idx(error, __FILE__, __LINE__, idx);
			continue;
		}

		ret = dregex_code_match(code, test->subject, &error);

		test_assert_cmp_idx(test->match_ret, ==, ret, idx);
		if (test->match_ret < 0)
			test_assert_strcmp_idx(test->error, error, idx);
		else if (ret < 0) {
			error = t_strdup_printf("Unexpected error: %s", error);
			test_assert_failed_idx(error, __FILE__, __LINE__, idx);
			continue;
		}
	}
	dregex_code_free(&code);
}

#define MATCH_CASE_FULL(pat, sub, err, cret, mret) \
	{ \
		.pattern = (pat), \
		.subject = (sub), \
		.replacement = NULL, \
		.result = NULL, \
		.error = (err), \
		.compile_ret = (cret), \
		.match_ret = (mret) \
	}
#define MATCH_CASE(pattern, subject) MATCH_CASE_FULL(pattern, subject, NULL, 0, 1)
#define MATCH_CASE_END { .pattern = NULL }

#define STR(x) x
#define REP(x) STR(x) STR(x) STR(x) STR(x) STR(x) STR(x) STR(x) STR(x) STR(x) STR(x)
#define REP10(x) REP(x) REP(x) REP(x) REP(x) REP(x) REP(x) REP(x) REP(x) REP(x) REP(x)

static void test_dregex_match(void)
{
	const struct test_case cases[] = {
		/* simple test case */
		MATCH_CASE(".*", "hello world"),
		/* .* matches empty string */
		MATCH_CASE_FULL(".*", "", NULL, 0, 0),
		/* but empty string does not match empty string */
		MATCH_CASE_FULL("", "", NULL, 0, 0),
		/* Match any single character except newline. */
		MATCH_CASE(".", "a"),
		MATCH_CASE_FULL(".", "\n", NULL, 0, 0),
		/* Bracket expression.  Match any one of the enclosed
		   characters.  A hypen (-) indicates a	range of
		   consecutive characters. */
		MATCH_CASE("[a-z]", "a"),
		MATCH_CASE_FULL("[a-z]", "A", NULL, 0, 0),
		/* Negated bracket expression. */
		MATCH_CASE("[^a-z]", "A"),
		MATCH_CASE_FULL("[^a-z]", "a", NULL, 0, 0),
		/* Character class */
		MATCH_CASE("^[[:alnum:]]+$", "abc123"),
		MATCH_CASE_FULL("^[[^:alnum:]]+$", "abc123", NULL, 0, 0),
		/* Unicode properties */
		MATCH_CASE("^\\p{L}$", "\xc3\xab"),
		MATCH_CASE("^\\pL$", "\xc3\xab"),
		/* Quantifiers */
		MATCH_CASE("^.$", "h"),
		MATCH_CASE("^.{2}$", "he"),
		MATCH_CASE("^.{2,3}$", "he"),
		MATCH_CASE("^.{2,3}$", "hel"),
		MATCH_CASE("^.+$", "hello"),
		MATCH_CASE_FULL("^.+$", "", NULL, 0, 0),
		/* Alternation and grouping */
		MATCH_CASE("^(hello|world)$", "hello"),
		MATCH_CASE("^(hello|world)$", "world"),
		MATCH_CASE_FULL("^(hello|world)$", "hi", NULL, 0, 0),
		/* test that we can find 'mojiretsu' (test string) from
		  'Kore wa tesuto mojiretsudesu.' (this is a test string) */
		MATCH_CASE(
			"\xe6\x96\x87\xe5\xad\x97\xe5\x88\x97",
			"\xe3\x81\x93\xe3\x82\x8c\xe3\x81\xaf\xe3\x83\x86\xe3"
			"\x82\xb9\xe3\x83\x88\xe6\x96\x87\xe5\xad\x97\xe5\x88"
			"\x97\xe3\x81\xa7\xe3\x81\x99\xe3\x80\x82"
		),
		/* test that we can find <U+1F60A> from <U+1F600><U+1F60A> */
		MATCH_CASE("\xef\x85\xa0""A", "\xef\x85\xa0""0\xef\x85\xa0""A"),
		/* binary matching */
		{
			.pattern = "\xef\x85\xa0""A",
			.subject = "\xef\x85\xa0""0\xef\x85\xa0""A",
			.error = "",
			.flags = DREGEX_ASCII_ONLY,
			.compile_ret = 0,
			.match_ret = 1,
		},
		{
			.pattern = ".*",
			.subject = "\xef\x85\xa0""0\xef\x85\xa0""A",
			.error = "",
			.flags = DREGEX_ASCII_ONLY,
			.compile_ret = 0,
			.match_ret = 1,
		},
		/* invalid utf-8 */
		MATCH_CASE_FULL(".*", "\xc2\xc2", "bad data value", 0, -1),
		/* two evil patterns */
		MATCH_CASE_FULL(
			"^([a-zA-Z0-9])(([\\-.]|[_]+)?([a-zA-Z0-9]+))*(@)"
			"{1}[a-z0-9]+[.]{1}(([a-z]{2,3})|([a-z]{2,3}[.]"
			"{1}[a-z]{2,3}))$",
			"thisisabstractly.andtotally.long.email@"
			REP10("a") "." REP10("a") "." REP10("a")
			".has",
			"match limit exceeded",
			0,
			-1
		),
		MATCH_CASE_FULL(
			"(a|a?)+",
			REP10("a") REP10("a"),
			"match limit exceeded",
			0,
			-1
		),
		/* IEEE.1003-2.1992 */
		MATCH_CASE("me(\\+.*)?@company\\.com",
			"me+hello@company.com"),
		MATCH_CASE("^[^[:lower:]]+$", "HELLO"),
		MATCH_CASE_FULL(
			"^[^[:lower:]]+$",
			"hello",
			NULL,
			0,
			0
		),
		MATCH_CASE("<(.*)@", "<simple-list@test.invalid>"),
		MATCH_CASE("^\\[(.*)\\] (.*)$", "[acme-users] [fwd]: hello, world"),
		MATCH_CASE_END
	};

	test_begin("matching");

	run_match_tests(cases);

	test_end();
}

static void run_replace_tests(const struct test_case *cases)
{
	unsigned int idx;
	struct dregex_code *code = dregex_code_create();
	string_t *dest = t_str_new(32);

	for(idx = 0; cases[idx].pattern != NULL; idx++) {
		const char *error = NULL;
		const struct test_case *test = &cases[idx];
		str_truncate(dest, 0);

		if (debug) {
			i_debug("pattern = %s, subject = %s, "
				"replacement = %s, result = %s",
				test->pattern, test->subject,
				test->replacement, test->result);
		}

		/* compile pattern */
		int ret = dregex_code_compile(code, test->pattern, test->flags,
					     &error);
		test_assert_cmp_idx(test->compile_ret, ==, ret, idx);
		if (test->compile_ret < 0) {
			test_assert_strcmp_idx(test->error, error, idx);
			continue;
		} else if (ret < 0) {
			error = t_strdup_printf("Unexpected error: %s", error);
			test_assert_failed_idx(error, __FILE__, __LINE__, idx);
			continue;
		}

		ret = dregex_code_replace(code, test->subject, test->replacement,
				         dest, test->flags, &error);

		test_assert_cmp_idx(test->match_ret, ==, ret, idx);
		if (test->match_ret < 0) {
			test_assert_strcmp_idx(test->error, error, idx);
			continue;
		} else if (ret < 0) {
			error = t_strdup_printf("Unexpected error: %s", error);
			test_assert_failed_idx(error, __FILE__, __LINE__, idx);
			continue;
		}
		test_assert_strcmp_idx(test->result, str_c(dest), idx);
	}
	dregex_code_free(&code);
}

#define REP_CASE_FULL(pat, sub, rep, res, err, cret, mret) \
	{ \
		.pattern = (pat), \
		.subject = (sub), \
		.replacement = (rep), \
		.result = (res), \
		.error = (err), \
		.compile_ret = (cret), \
		.match_ret = (mret) \
	}
#define REP_CASE(pattern, subject, replacement, result) \
	REP_CASE_FULL(pattern, subject, replacement, result, NULL, 0, 1)
#define REP_CASE_END { .pattern = NULL }

static void test_dregex_replace(void)
{
	const struct test_case cases[] = {
		/* simple replacement */
		REP_CASE(".*", "hello world", "world hello", "world hello"),
		/* simple swap */
		REP_CASE("(.*) (.*)", "hello world", "$2 $1", "world hello"),
		/* partial replace */
		REP_CASE("hello .*", "hello world", "$0", "hello world"),
		/* simple utf-8 test,
		 * '<U+1F600> <U+1F60A>' to '<U+1F60A> <U+1F600>' */
		REP_CASE(
			"(.*) (.*)",
			"\xef\x85\xa0""0 \xef\x85\xa0""A",
			"$2 $1",
			"\xef\x85\xa0""A \xef\x85\xa0""0"
		),
		/* Invalid back reference */
		REP_CASE_FULL(
			"hello .*",
			"hello world",
			"$5",
			"",
			"unknown substring",
			0,
			-1
		),
		REP_CASE_END
	};

	test_begin("replacing");

	run_replace_tests(cases);

	test_end();
}

int main(void)
{
	void (*const tests[])(void) = {
		test_dregex_match,
		test_dregex_replace,
		NULL
	};

	return test_run(tests);
}

#else

int main(void) {
	return 0;
}

#endif
