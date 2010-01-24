/* Copyright (c) 2008-2010 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "imap-match.h"
#include "test-common.h"

struct test_imap_match {
	const char *pattern;
	const char *input;
	enum imap_match_result result;
};

static void test_imap_match(void)
{
	struct test_imap_match test[] = {
		{ "", "", IMAP_MATCH_YES },
		{ "a", "b", IMAP_MATCH_NO },
		{ "foo", "foo", IMAP_MATCH_YES },
		{ "foo", "foo/", IMAP_MATCH_PARENT },
		{ "%", "", IMAP_MATCH_YES },
		{ "%", "foo", IMAP_MATCH_YES },
		{ "%", "foo/", IMAP_MATCH_PARENT },
		{ "%/", "foo/", IMAP_MATCH_YES },
		{ "%", "foo/bar", IMAP_MATCH_PARENT },
		{ "%/%", "foo", IMAP_MATCH_CHILDREN },
		{ "%/%", "foo/", IMAP_MATCH_YES },
		{ "foo/bar/%", "foo", IMAP_MATCH_CHILDREN },
		{ "foo/bar/%", "foo/", IMAP_MATCH_CHILDREN },
		{ "foo*", "foo", IMAP_MATCH_YES },
		{ "foo*", "foo/", IMAP_MATCH_YES },
		{ "foo*", "fobo", IMAP_MATCH_NO },
		{ "*foo*", "bar/foo/", IMAP_MATCH_YES },
		{ "*foo*", "fobo", IMAP_MATCH_CHILDREN },
		{ "foo*bar", "foobar/baz", IMAP_MATCH_CHILDREN | IMAP_MATCH_PARENT },
		{ "*foo*", "fobo", IMAP_MATCH_CHILDREN },
		{ "%/%/%", "foo/", IMAP_MATCH_CHILDREN },
		{ "%/%o/%", "foo/", IMAP_MATCH_CHILDREN },
		{ "%/%o/%", "foo", IMAP_MATCH_CHILDREN },
		{ "inbox", "inbox", IMAP_MATCH_YES },
		{ "inbox", "INBOX", IMAP_MATCH_NO }
	};
	struct test_imap_match inbox_test[] = {
		{ "inbox", "inbox", IMAP_MATCH_YES },
		{ "inbox", "iNbOx", IMAP_MATCH_YES },
		{ "i%X", "iNbOx", IMAP_MATCH_YES },
		{ "%I%N%B%O%X%", "inbox", IMAP_MATCH_YES },
		{ "i%X/foo", "iNbOx/foo", IMAP_MATCH_YES },
		{ "%I%N%B%O%X%/foo", "inbox/foo", IMAP_MATCH_YES },
		{ "i%X/foo", "inbx/foo", IMAP_MATCH_NO }
	};
	struct imap_match_glob *glob;
	unsigned int i;
	enum imap_match_result result;

	/* first try tests without inboxcasing */
	for (i = 0; i < N_ELEMENTS(test); i++) {
		glob = imap_match_init(default_pool, test[i].pattern,
				       FALSE, '/');
		result = imap_match(glob, test[i].input);
		imap_match_deinit(&glob);

		test_out(t_strdup_printf("imap_match(%d)", i), 
			 result == test[i].result);
	}

	/* inboxcasing tests */
	for (i = 0; i < N_ELEMENTS(inbox_test); i++) {
		glob = imap_match_init(default_pool, inbox_test[i].pattern,
				       TRUE, '/');
		result = imap_match(glob, inbox_test[i].input);
		imap_match_deinit(&glob);

		test_out(t_strdup_printf("imap_match(inboxcase, %d)", i),
			 result == inbox_test[i].result);
	}
}

int main(void)
{
	static void (*test_functions[])(void) = {
		test_imap_match,
		NULL
	};
	return test_run(test_functions);
}
