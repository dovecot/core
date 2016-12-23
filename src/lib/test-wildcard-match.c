/* Copyright (c) 2014-2016 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "wildcard-match.h"

static const struct {
	const char *data;
	const char *mask;
	bool result;
} tests[] = {
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

void test_wildcard_match(void)
{
	unsigned int i;

	test_begin("wildcard_match()");
	for (i = 0; i < N_ELEMENTS(tests); i++) {
		test_assert_idx(wildcard_match(tests[i].data, tests[i].mask) == tests[i].result, i);
	}
	test_end();
}
