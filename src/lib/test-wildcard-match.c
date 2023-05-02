/* Copyright (c) 2014-2018 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "wildcard-match.h"

static const struct {
	const char *data;
	const char *mask;
	bool result;
} tests_common[] = {
	{ "foo", "*", TRUE },
	{ "foo", "*foo*", TRUE },
	{ "foo", "foo", TRUE },
	{ "foo", "f*o*o", TRUE },
	{ "foo", "f??", TRUE },
	{ "foo", "f?o", TRUE },
	{ "foo", "*??", TRUE },
	{ "foo", "???", TRUE },
	{ "foo", "f??*", TRUE },
	{ "foo", "???*", TRUE },

	{ "foo", "", FALSE },
	{ "foo", "f", FALSE },
	{ "foo", "fo", FALSE },
	{ "foo", "fooo", FALSE },
	{ "foo", "????", FALSE },
	{ "foo", "f*o*o*o", FALSE },
	{ "foo", "f???*", FALSE },

	{ "*foo", "foo", FALSE },
	{ "foo*", "foo", FALSE },
	{ "*foo*", "foo", FALSE },

	{ "", "*", TRUE },
	{ "", "", TRUE },
	{ "", "?", FALSE }
};

static const struct {
	const char *data;
	const char *mask;
	bool result;
} tests_unescaped[] = {
	{ "f*o", "f*o", TRUE },
	{ "f*o", "f\\*o", FALSE },
};

static const struct {
	const char *data;
	const char *mask;
	bool result;
} tests_escaped[] = {
	{ "f*o", "f*o", TRUE },
	{ "f*o", "f\\*o", TRUE },
	{ "f?o", "f\\*o", FALSE },
	{ "f?o", "f\\?o", TRUE },
	{ "f*o", "f\\*", FALSE },
	{ "f*", "f\\", FALSE },
	{ "f\\*o", "f\\*o", FALSE },
	{ "f\\*o", "f\\\\*", TRUE },
	{ "f\\*o", "f\\\\*o", TRUE },
	{ "f\\*o", "f\\\\\\*o", TRUE },
	{ "f\\*o", "f\\?o", FALSE },
	{ "f\\*o", "f\\\\?o", TRUE },
	{ "f\\*o", "f\\\\\\?o", FALSE },
	{ "f\\", "f\\", TRUE },
	{ "\\\\?", "?\\\\?", TRUE },
};

void test_wildcard_match(void)
{
	unsigned int i;

	test_begin("wildcard_match()");
	for (i = 0; i < N_ELEMENTS(tests_common); i++) {
		test_assert_idx(wildcard_match(tests_common[i].data,
					       tests_common[i].mask) ==
				tests_common[i].result, i);
		test_assert_idx(wildcard_match_escaped(tests_common[i].data,
						       tests_common[i].mask) ==
				tests_common[i].result, i);
	}

	for (i = 0; i < N_ELEMENTS(tests_unescaped); i++) {
		test_assert_idx(wildcard_match(tests_unescaped[i].data,
					       tests_unescaped[i].mask) ==
				tests_unescaped[i].result, i);
	}

	for (i = 0; i < N_ELEMENTS(tests_escaped); i++) {
		test_assert_idx(wildcard_match_escaped(tests_escaped[i].data,
						       tests_escaped[i].mask) ==
				tests_escaped[i].result, i);
	}
	test_assert(!wildcard_is_literal("\\*foo\\?bar\\?"));
	test_assert(wildcard_is_escaped_literal("\\*foo\\?bar\\?"));
	test_assert(!wildcard_is_escaped_literal("*foo"));
	test_end();

	test_begin("wildcard_str_escape()");
	const char *foo = "foo";
	test_assert(wildcard_str_escape(foo) == foo);
	test_assert_strcmp(wildcard_str_escape("foo?"), "foo\\?");
	test_assert_strcmp(wildcard_str_escape("foo*"), "foo\\*");
	test_assert_strcmp(wildcard_str_escape("foo\\"), "foo\\\\");
	test_assert_strcmp(wildcard_str_escape("foo\\"), "foo\\\\");
	test_assert_strcmp(wildcard_str_escape("\\f*o?o'\"x"), "\\\\f\\*o\\?o\\'\\\"x");
	test_end();
}
