/* Copyright (c) 2009-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "mail-types.h"
#include "imap-util.h"
#include "test-common.h"

static void test_imap_parse_system_flag(void)
{
	test_begin("imap_parse_system_flag");
	test_assert(imap_parse_system_flag("\\aNswered") == MAIL_ANSWERED);
	test_assert(imap_parse_system_flag("\\fLagged") == MAIL_FLAGGED);
	test_assert(imap_parse_system_flag("\\dEleted") == MAIL_DELETED);
	test_assert(imap_parse_system_flag("\\sEen") == MAIL_SEEN);
	test_assert(imap_parse_system_flag("\\dRaft") == MAIL_DRAFT);
	test_assert(imap_parse_system_flag("\\rEcent") == MAIL_RECENT);
	test_assert(imap_parse_system_flag("answered") == 0);
	test_assert(imap_parse_system_flag("\\broken") == 0);
	test_assert(imap_parse_system_flag("\\") == 0);
	test_assert(imap_parse_system_flag("") == 0);
	test_end();
}

int main(void)
{
	static void (*test_functions[])(void) = {
		test_imap_parse_system_flag,
		NULL
	};
	return test_run(test_functions);
}
