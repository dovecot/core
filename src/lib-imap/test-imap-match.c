/* Copyright (c) 2008-2011 Dovecot authors, see the included COPYING file */

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
	struct imap_match_glob *glob, *glob2;
	unsigned int i;
	pool_t pool;

	pool = pool_alloconly_create("imap match", 1024);

	/* first try tests without inboxcasing */
	test_begin("imap match");
	for (i = 0; i < N_ELEMENTS(test); i++) {
		glob = imap_match_init(pool, test[i].pattern,
				       FALSE, '/');
		test_assert(imap_match(glob, test[i].input) == test[i].result);

		glob2 = imap_match_dup(default_pool, glob);
		test_assert(imap_match_globs_equal(glob, glob2));
		p_clear(pool);

		/* test the dup after clearing first one's memory */
		test_assert(imap_match(glob2, test[i].input) == test[i].result);
		imap_match_deinit(&glob2);
	}

	/* inboxcasing tests */
	for (i = 0; i < N_ELEMENTS(inbox_test); i++) {
		glob = imap_match_init(pool, inbox_test[i].pattern,
				       TRUE, '/');
		test_assert(imap_match(glob, inbox_test[i].input) == inbox_test[i].result);

		glob2 = imap_match_dup(default_pool, glob);
		test_assert(imap_match_globs_equal(glob, glob2));
		p_clear(pool);

		/* test the dup after clearing first one's memory */
		test_assert(imap_match(glob2, inbox_test[i].input) == inbox_test[i].result);
		imap_match_deinit(&glob2);
	}
	pool_unref(&pool);
	test_end();
}

static void test_imap_match_globs_equal(void)
{
	struct imap_match_glob *glob;
	pool_t pool;

	pool = pool_alloconly_create("imap match globs equal", 1024);
	test_begin("imap match globs equal");

	glob = imap_match_init(pool, "1", FALSE, '/');
	test_assert(imap_match_globs_equal(glob,
		imap_match_init(pool, "1", FALSE, '/')));
	test_assert(imap_match_globs_equal(glob,
		imap_match_init(pool, "1", TRUE, '/')));
	test_assert(!imap_match_globs_equal(glob,
		imap_match_init(pool, "1", FALSE, '.')));
	test_assert(!imap_match_globs_equal(glob,
		imap_match_init(pool, "11", FALSE, '/')));

	glob = imap_match_init(pool, "in%", TRUE, '/');
	test_assert(!imap_match_globs_equal(glob,
		imap_match_init(pool, "in%", FALSE, '/')));
	test_assert(!imap_match_globs_equal(glob,
		imap_match_init(pool, "In%", TRUE, '/')));

	pool_unref(&pool);
	test_end();
}

int main(void)
{
	static void (*test_functions[])(void) = {
		test_imap_match,
		test_imap_match_globs_equal,
		NULL
	};
	return test_run(test_functions);
}
