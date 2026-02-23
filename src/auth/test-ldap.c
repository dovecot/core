/* Copyright (c) 2026 Dovecot authors, see the included COPYING file */

#include "test-auth.h"

#ifdef HAVE_LDAP
#include "db-ldap.h"

static void test_ldap_escape(void)
{
	struct {
		const char *input;
		const char *output;
	} tests[] = {
		{ "", "" },
		{ " ", "\\20" },
		{ "  ", "\\20\\20" },
		{ "foo ", "foo\\20" },
		{ ",", "\\2c" },
		{ "s p a c e", "s p a c e" },
		{ "# start-end#", "\\23 start-end#" },
		{ "  start-end2  ", "\\20 start-end2 \\20" },
		{ "middle:,+\"\\<>;=", "middle:\\2c\\2b\\22\\5c\\3c\\3e\\3b\\3d" },
		{ "valid-utf8:\xc3\xb1", "valid-utf8:\xc3\xb1" },
		{ "Bad \xFF Characters", "Bad \xEF\xBF\xBD Characters" },
	};
	test_begin("ldap_escape()");
	for (unsigned int i = 0; i < N_ELEMENTS(tests); i++) {
		test_assert_strcmp_idx(ldap_escape(tests[i].input, NULL),
				       tests[i].output, i);
	}
	test_end();
}

void test_db_ldap(void)
{
	test_ldap_escape();
}

#endif
