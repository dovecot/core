/* Copyright (c) 2008-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "unichar.h"
#include "imap-match.h"
#include "imap-utf7.h"
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

static void test_imap_utf7(void)
{
	static const char *to_utf7[] = {
		"&&x&&", "&-&-x&-&-",
		"~peter/mail/台北/日本語", "~peter/mail/&U,BTFw-/&ZeVnLIqe-",
		"tietäjä", "tiet&AOQ-j&AOQ-",
		"p��", NULL,
		NULL
	};
	static const char *invalid_utf7[] = {
		"&Jjo!",
		"&U,BTFw-&ZeVnLIqe-",
		NULL
	};
	string_t *src, *dest;
	const char *orig_src;
	unsigned int i, j;
	unichar_t chr;
	bool success, all_success = TRUE;

	src = t_str_new(256);
	dest = t_str_new(256);

	for (i = 0; to_utf7[i] != NULL; i += 2) {
		str_truncate(dest, 0);
		if (imap_utf8_to_utf7(to_utf7[i], dest) < 0)
			success = to_utf7[i+1] == NULL;
		else {
			success = to_utf7[i+1] != NULL &&
				strcmp(to_utf7[i+1], str_c(dest)) == 0;
		}
		if (!success) {
			test_out(t_strdup_printf("imap_utf8_to_utf7(%d)", i/2),
				 FALSE);
			all_success = FALSE;
		} else if (to_utf7[i+1] != NULL) {
			str_truncate(dest, 0);
			if (imap_utf7_to_utf8(to_utf7[i+1], dest) < 0 ||
			    strcmp(to_utf7[i], str_c(dest)) != 0) {
				test_out(t_strdup_printf("imap_utf7_to_utf8(%d)", i/2),
					 FALSE);
				all_success = FALSE;
			}
		}
	}
	if (all_success)
		test_out("imap_utf8_to_utf7()", TRUE);

	success = TRUE;
	for (chr = 0xffff; chr <= 0x10010; chr++) {
		for (i = 1; i <= 10; i++) {
			str_truncate(src, 0);
			str_truncate(dest, 0);
			for (j = 0; j < i; j++) {
				if (j % 3 == 0)
					str_append_c(src, 'x');
				if (j % 5 == 0)
					str_append_c(src, '&');
				uni_ucs4_to_utf8_c(chr, src);
			}

			orig_src = t_strdup(str_c(src));
			str_truncate(src, 0);

			if (imap_utf8_to_utf7(orig_src, dest) < 0)
				success = FALSE;
			else if (imap_utf7_to_utf8(str_c(dest), src) < 0)
				success = FALSE;
			else
				success = strcmp(str_c(src), orig_src) == 0;
			if (!success)
				goto end;
		}
	}
end:
	test_out("imap_utf7_to_utf8(reverse)", success);
	for (i = 0; invalid_utf7[i] != NULL; i++) {
		str_truncate(dest, 0);
		if (imap_utf7_to_utf8(invalid_utf7[i], dest) == 0) {
			test_out(t_strdup_printf("imap_utf7_to_utf8(invalid.%d)", i),
				 FALSE);
			all_success = FALSE;
		}
	}
	if (all_success)
		test_out("imap_utf7_to_utf8(invalid)", TRUE);
}

int main(void)
{
	static void (*test_functions[])(void) = {
		test_imap_match,
		test_imap_utf7,

		NULL
	};
	return test_run(test_functions);
}
