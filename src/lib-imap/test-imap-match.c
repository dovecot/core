/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "str.h"
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
		{ "inbox", "INBOX", IMAP_MATCH_NO },
		/* Grapheme cluster: normal a */
		{ "ha*", "ha", IMAP_MATCH_YES },
		/* Grapheme cluster: a with diacritic; precomposed (NFC) */
		{ "ha*", "h\xC3\xA3", IMAP_MATCH_NO },
		/* Grapheme cluster: a with diacritic; not composable
		   -> More than a single code point per grapheme cluster.
		   -> This is where a naive matching algorithm fails. */
		{ "ha*", "ha\xCC\x85", IMAP_MATCH_NO },
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

static void test_imap_match_no_redos(void)
{
	/* Verify that patterns with many % wildcards followed by a literal
	   that repeats in the data do not cause exponential backtracking.
	   The NFA simulation is O(n_data * n_pattern) regardless of wildcard
	   count, so even very large pattern/data combinations must complete
	   quickly. */
	struct imap_match_glob *glob;
	pool_t pool;
	const unsigned int wildcard_count = 1000;

	pool = pool_alloconly_create("imap match redos", 1024);
	test_begin("imap match no redos");

	/* 255-character single-hierarchy mailbox name */
	string_t *mailbox_name = str_new(pool, 256);
	for (unsigned int i = 0; i < 255; i++)
		str_append_c(mailbox_name, 'a');

	/* N x "%a" against 255 "a"s: match when N <= 255 */
	string_t *pattern = str_new(pool, wildcard_count * 2 + 10);
	for (unsigned int i = 0; i < 255; i++)
		str_append(pattern, "%a");
	glob = imap_match_init(pool, str_c(pattern), FALSE, '/');
	test_assert(imap_match(glob, str_c(mailbox_name)) == IMAP_MATCH_YES);

	/* More wildcards than data characters -> non-match */
	str_truncate(pattern, 0);
	for (unsigned int i = 0; i < wildcard_count; i++)
		str_append(pattern, "%a");
	glob = imap_match_init(pool, str_c(pattern), FALSE, '/');
	test_assert(imap_match(glob, str_c(mailbox_name)) == IMAP_MATCH_NO);

	/* Large N x "%a" + "b" against 255 "a"s: no match */
	str_append_c(pattern, 'b');
	glob = imap_match_init(pool, str_c(pattern), FALSE, '/');
	test_assert(imap_match(glob, str_c(mailbox_name)) == IMAP_MATCH_NO);

	/* Same with "*" wildcards: returns CHILDREN because the pattern
	   could match something under the current name */
	str_truncate(pattern, 0);
	for (unsigned int i = 0; i < wildcard_count; i++)
		str_append(pattern, "*a");
	str_append_c(pattern, 'b');
	glob = imap_match_init(pool, str_c(pattern), FALSE, '/');
	test_assert(imap_match(glob, str_c(mailbox_name)) == IMAP_MATCH_CHILDREN);
	p_clear(pool);

	/* Positive case: 5 x "%a" + "b" should match "aaaaab" */
	glob = imap_match_init(pool, "%a%a%a%a%ab", FALSE, '/');
	test_assert(imap_match(glob, "aaaaab") == IMAP_MATCH_YES);
	p_clear(pool);

	/* Negative case: 5 x "%a" + "b" does not match "aaaaa" (no trailing b) */
	glob = imap_match_init(pool, "%a%a%a%a%ab", FALSE, '/');
	test_assert(imap_match(glob, "aaaaa") == IMAP_MATCH_NO);

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
	static void (*const test_functions[])(void) = {
		test_imap_match,
		test_imap_match_no_redos,
		test_imap_match_globs_equal,
		NULL
	};
	return test_run(test_functions);
}
