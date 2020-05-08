/* Copyright (c) 2017-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "auth-settings.h"
#include "test-auth.h"
#include "auth-request.h"

void test_username_filter(void)
{
	const struct {
		const char *filter;
		const char *input;
		bool accepted;
	} cases[] = {
		{ "", "", TRUE },
		{ "*", "", TRUE },
		{ "", "testuser1", TRUE },
		{ "*", "testuser1", TRUE },
		{ "!*", "testuser1", FALSE },
		{ "!*", "", FALSE },
		{ "*@*", "", FALSE },
		{ "*@*", "@", TRUE },
		{ "!*@*", "@", FALSE },
		{ "!*@*", "", TRUE },
		{ "*@*", "testuser1", FALSE },
		{ "!*@*", "testuser1", TRUE },
		{ "*@*", "testuser1@testdomain", TRUE },
		{ "!*@*", "testuser1@testdomain", FALSE },
		{ "*@testdomain *@testdomain2", "testuser1@testdomain", TRUE },
		{ "*@testdomain *@testdomain2", "testuser1@testdomain2", TRUE },
		{ "*@testdomain *@testdomain2", "testuser1@testdomain3", FALSE },
		{ "!testuser@testdomain *@testdomain", "testuser@testdomain", FALSE },
		{ "!testuser@testdomain *@testdomain", "testuser2@testdomain", TRUE },
		{ "*@testdomain !testuser@testdomain !testuser2@testdomain", "testuser@testdomain", FALSE },
		{ "*@testdomain !testuser@testdomain !testuser2@testdomain", "testuser3@testdomain", TRUE },
		{ "!testuser@testdomain !testuser2@testdomain", "testuser", TRUE },
		{ "!testuser@testdomain !testuser2@testdomain", "testuser@testdomain", FALSE },
		{ "!testuser@testdomain *@testdomain !testuser2@testdomain", "testuser3@testdomain", TRUE },
		{ "!testuser@testdomain *@testdomain !testuser2@testdomain", "testuser@testdomain", FALSE },
	};

	test_begin("test username_filter");

	for(size_t i = 0; i < N_ELEMENTS(cases); i++) {
		const char *const *filter = t_strsplit_spaces(cases[i].filter, " ,");
		test_assert_idx(auth_request_username_accepted(filter, cases[i].input) == cases[i].accepted, i);
	}

	test_end();
}
