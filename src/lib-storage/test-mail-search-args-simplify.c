/* Copyright (c) 2015-2016 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "test-common.h"
#include "mail-search-build.h"
#include "mail-search-parser.h"
#include "mail-search.h"

static const struct {
	const char *input;
	const char *output;
} tests[] = {
	{ "ALL", "ALL" },
	{ "NOT ALL", "NOT ALL" },
	{ "ALL NOT ALL", "NOT ALL" },
	{ "ALL NOT ALL TEXT foo", "NOT ALL" },
	{ "OR ALL NOT ALL", "ALL" },
	{ "OR ALL OR NOT ALL TEXT foo", "ALL" },
	{ "OR ALL OR TEXT foo TEXT bar", "ALL" },
	{ "OR TEXT FOO ( ALL NOT ALL )", "TEXT FOO" },
	{ "TEXT FOO OR ALL NOT ALL", "TEXT FOO" },

	{ "TEXT foo", "TEXT foo" },
	{ "( TEXT foo )", "TEXT foo" },
	{ "( ( TEXT foo ) )", "TEXT foo" },
	{ "( ( TEXT foo ) ( TEXT bar ) )", "TEXT foo TEXT bar" },

	{ "OR ( TEXT foo ) ( TEXT bar )", "(OR TEXT foo TEXT bar)" },
	{ "OR ( TEXT foo ) OR ( TEXT bar ) ( TEXT baz )",
	  "(OR TEXT foo OR TEXT bar TEXT baz)" },
	{ "OR ( ( TEXT foo TEXT foo2 ) ) ( ( TEXT bar ( TEXT baz ) ) )",
	  "(OR (TEXT foo TEXT foo2) (TEXT bar TEXT baz))" },

	{ "NOT ( TEXT foo )", "NOT TEXT foo" },
	{ "NOT ( NOT ( TEXT foo ) )", "TEXT foo" },
	{ "NOT OR ( TEXT foo ) ( TEXT bar )", "NOT TEXT foo NOT TEXT bar" },
	{ "NOT ( OR ( TEXT foo ) ( TEXT bar ) )", "NOT TEXT foo NOT TEXT bar" },
	{ "NOT ( TEXT foo TEXT bar )", "(OR NOT TEXT foo NOT TEXT bar)" },

	{ "ANSWERED FLAGGED SEEN", "(ANSWERED FLAGGED SEEN)" },
	{ "OR ( ANSWERED FLAGGED SEEN ) DRAFT", "(OR (ANSWERED FLAGGED SEEN) (DRAFT))" },
	{ "ANSWERED TEXT foo FLAGGED SEEN", "(ANSWERED FLAGGED SEEN) TEXT foo" },
	{ "NOT ( ANSWERED FLAGGED SEEN )", "NOT (ANSWERED FLAGGED SEEN)" },
	{ "OR NOT ANSWERED OR NOT FLAGGED NOT SEEN", "NOT (ANSWERED FLAGGED SEEN)" },
	{ "ANSWERED NOT FLAGGED SEEN NOT DRAFT", "(ANSWERED SEEN) NOT (FLAGGED) NOT (DRAFT)" },
	{ "OR NOT ANSWERED NOT SEEN", "NOT (ANSWERED SEEN)" },

	{ "1:* 1:*", "ALL" },
	{ "OR 1:5 6:*", "ALL" },

	{ "UID 1:* UID 1:*", "ALL" },
	{ "OR UID 1:5 UID 6:*", "ALL" },

	{ "2:* 2:*", "2:4294967295" },
	{ "OR 2:* 2:*", "2:4294967295" },

	{ "UID 2:* UID 2:*", "UID 2:4294967295" },
	{ "OR UID 2:* UID 2:*", "UID 2:4294967295" },

	{ "1:5 6:7", "NOT ALL" },
	{ "1:5 3:7", "3:5" },
	{ "1:5 3:7 4:9", "4:5" },
	{ "1:5 OR 3:4 4:6", "3:5" },
	{ "OR 1 2", "1:2" },
	{ "NOT 1,3:5", "2,6:4294967294" },
	{ "NOT 1:100 NOT 50:200", "201:4294967294" },
	{ "OR NOT 1:100 NOT 50:200", "1:49,101:4294967294" },

	{ "UID 1:5 UID 6:7", "NOT ALL" },
	{ "UID 1:5 UID 3:7", "UID 3:5" },
	{ "OR UID 1 UID 2", "UID 1:2" },
	{ "NOT UID 1,3:5", "UID 2,6:4294967294" },

	{ "1:5 UID 10:20", "1:5 UID 10:20" },
	{ "1:5 NOT UID 10:20", "1:5 UID 1:9,21:4294967294" },

	{ "ALL NOT UID 3:*", "NOT UID 3:4294967295" },
	{ "NOT 1:10 NOT *", "11:4294967294 NOT 4294967295" },

	{ "BEFORE 03-Aug-2014 BEFORE 01-Aug-2014 BEFORE 02-Aug-2014", "BEFORE \"01-Aug-2014\"" },
	{ "OR BEFORE 01-Aug-2014 BEFORE 02-Aug-2014", "BEFORE \"02-Aug-2014\"" },
	{ "OR BEFORE 01-Aug-2014 OR BEFORE 03-Aug-2014 BEFORE 02-Aug-2014", "BEFORE \"03-Aug-2014\"" },
	{ "BEFORE 03-Aug-2014 NOT BEFORE 01-Aug-2014 BEFORE 02-Aug-2014", "BEFORE \"02-Aug-2014\" NOT BEFORE \"01-Aug-2014\"" },
	{ "SENTBEFORE 03-Aug-2014 SENTBEFORE 01-Aug-2014 SENTBEFORE 02-Aug-2014", "SENTBEFORE \"01-Aug-2014\"" },
	{ "SENTBEFORE 03-Aug-2014 BEFORE 01-Aug-2014 SENTBEFORE 02-Aug-2014", "SENTBEFORE \"02-Aug-2014\" BEFORE \"01-Aug-2014\"" },

	{ "ON 03-Aug-2014 ON 03-Aug-2014", "ON \"03-Aug-2014\"" },
	{ "ON 03-Aug-2014 ON 04-Aug-2014", "ON \"03-Aug-2014\" ON \"04-Aug-2014\"" }, /* this could be replaced with e.g. NOT ALL */
	{ "OR ON 03-Aug-2014 ON 04-Aug-2014", "(OR ON \"03-Aug-2014\" ON \"04-Aug-2014\")" },

	{ "SINCE 03-Aug-2014 SINCE 01-Aug-2014 SINCE 02-Aug-2014", "SINCE \"03-Aug-2014\"" },
	{ "OR SINCE 01-Aug-2014 SINCE 02-Aug-2014", "SINCE \"01-Aug-2014\"" },
	{ "OR SINCE 01-Aug-2014 OR SINCE 03-Aug-2014 SINCE 02-Aug-2014", "SINCE \"01-Aug-2014\"" },
	{ "SINCE 03-Aug-2014 NOT SINCE 01-Aug-2014 SINCE 02-Aug-2014", "SINCE \"03-Aug-2014\" NOT SINCE \"01-Aug-2014\"" },
	{ "SENTSINCE 03-Aug-2014 SENTSINCE 01-Aug-2014 SENTSINCE 02-Aug-2014", "SENTSINCE \"03-Aug-2014\"" },
	{ "SENTSINCE 03-Aug-2014 SINCE 01-Aug-2014 SENTSINCE 02-Aug-2014", "SENTSINCE \"03-Aug-2014\" SINCE \"01-Aug-2014\"" },

	{ "SMALLER 1 SMALLER 2", "SMALLER 1" },
	{ "OR SMALLER 1 SMALLER 2", "SMALLER 2" },
	{ "OR SMALLER 1 OR SMALLER 3 SMALLER 2", "SMALLER 3" },
	{ "SMALLER 3 NOT SMALLER 1 SMALLER 2", "SMALLER 2 NOT SMALLER 1" },
	{ "SMALLER 3 LARGER 5", "SMALLER 3 LARGER 5" }, /* this could be replaced with e.g. NOT ALL */
	{ "OR SMALLER 3 LARGER 5", "(OR SMALLER 3 LARGER 5)" },

	{ "LARGER 3 LARGER 1 LARGER 2", "LARGER 3" },
	{ "OR LARGER 1 LARGER 2", "LARGER 1" },
	{ "OR LARGER 1 OR LARGER 3 LARGER 2", "LARGER 1" },
	{ "LARGER 3 NOT LARGER 1 LARGER 2", "LARGER 3 NOT LARGER 1" },

	{ "SUBJECT foo SUBJECT foo", "SUBJECT foo" },
	{ "SUBJECT foo SUBJECT foob", "SUBJECT foo SUBJECT foob" },
	{ "OR SUBJECT foo SUBJECT foo", "SUBJECT foo" },
	{ "FROM foo FROM foo", "FROM foo" },
	{ "FROM foo FROM bar", "FROM foo FROM bar" },
	{ "FROM foo TO foo", "FROM foo TO foo" },

	{ "TEXT foo TEXT foo", "TEXT foo" },
	{ "TEXT foo TEXT foob", "TEXT foo TEXT foob" },
	{ "OR TEXT foo TEXT foo", "TEXT foo" },
	{ "TEXT foo NOT TEXT foo TEXT foo NOT TEXT foo", "TEXT foo NOT TEXT foo" },
	{ "BODY foo BODY foo", "BODY foo" },
	{ "OR BODY foo BODY foo", "BODY foo" },
	{ "TEXT foo BODY foo", "TEXT foo BODY foo" },
	{ "OR ( TEXT foo OR TEXT foo TEXT foo ) ( TEXT foo ( TEXT foo ) )", "TEXT foo" },

	/* value="" tests */
	{ "HEADER foo ", "HEADER FOO \"\"" },
	{ "SUBJECT ", "SUBJECT \"\"" },
	{ "BODY ", "ALL" },
	{ "TEXT ", "ALL" },
	{ "HEADER foo .", "HEADER FOO ." },
	{ "SUBJECT .", "SUBJECT ." },
	{ "BODY .", "BODY ." },
	{ "TEXT .", "TEXT ." },

	/* OR: drop redundant args */
	{ "OR ( TEXT common1 TEXT unique1 ) TEXT common1", "TEXT common1" },
	{ "OR ( TEXT unique1 TEXT common1 ) TEXT common1", "TEXT common1" },
	{ "OR TEXT common1 ( TEXT common1 TEXT unique1 )", "TEXT common1" },
	{ "OR TEXT common1 ( TEXT unique1 TEXT common1 )", "TEXT common1" },
	{ "OR ( TEXT common1 TEXT common2 ) ( TEXT common1 TEXT common2 TEXT unique1 )", "TEXT common1 TEXT common2" },
	{ "OR TEXT common1 OR ( TEXT unique1 TEXT common1 ) ( TEXT unique3 TEXT common1 )", "TEXT common1" },

	/* OR: extract common AND */
	{ "OR ( TEXT common1 TEXT unique1 ) ( TEXT common1 TEXT unique2 )", "(OR TEXT unique1 TEXT unique2) TEXT common1" },
	{ "OR ( TEXT unique1 TEXT common1 ) ( TEXT unique2 TEXT common1 )", "(OR TEXT unique1 TEXT unique2) TEXT common1" },
	{ "OR ( TEXT common1 TEXT unique1 ) ( TEXT unique2 TEXT common1 )", "(OR TEXT unique1 TEXT unique2) TEXT common1" },
	{ "OR ( TEXT unique1 TEXT common1 ) ( TEXT common1 TEXT unique2 )", "(OR TEXT unique1 TEXT unique2) TEXT common1" },

	{ "OR ( TEXT unique1 TEXT common1 ) ( TEXT common1 TEXT unique2 TEXT unique3 )", "(OR TEXT unique1 (TEXT unique2 TEXT unique3)) TEXT common1" },
	{ "OR ( TEXT common1 TEXT common2 TEXT unique1 ) ( TEXT common1 TEXT common2 TEXT unique2 )", "(OR TEXT unique1 TEXT unique2) TEXT common2 TEXT common1" },
	{ "OR ( TEXT common1 TEXT common2 TEXT unique1 TEXT unique2 ) ( TEXT common1 TEXT common2 TEXT unique3 TEXT unique4 )", "(OR (TEXT unique1 TEXT unique2) (TEXT unique3 TEXT unique4)) TEXT common2 TEXT common1" },

	/* non-matching cases */
	{ "OR ( TEXT unique1 TEXT unique2 ) TEXT unique3", "(OR (TEXT unique1 TEXT unique2) TEXT unique3)" },
	{ "OR ( TEXT unique1 TEXT unique2 ) ( TEXT unique3 TEXT unique4 )", "(OR (TEXT unique1 TEXT unique2) (TEXT unique3 TEXT unique4))" },
	{ "OR ( TEXT common1 TEXT unique1 ) OR ( TEXT common1 TEXT unique2 ) TEXT unique3", "(OR (TEXT common1 TEXT unique1) OR (TEXT common1 TEXT unique2) TEXT unique3)" },
	{ "OR ( TEXT common1 TEXT unique1 ) OR ( TEXT common1 TEXT common2 ) ( TEXT common2 TEXT unique2 )", "(OR (TEXT common1 TEXT unique1) OR (TEXT common1 TEXT common2) (TEXT common2 TEXT unique2))" },

	/* SUB: drop redundant args */
	{ "( OR TEXT common1 TEXT unique1 ) TEXT common1", "TEXT common1" },
	{ "( OR TEXT unique1 TEXT common1 ) TEXT common1", "TEXT common1" },
	{ "TEXT common1 ( OR TEXT common1 TEXT unique1 )", "TEXT common1" },
	{ "TEXT common1 ( OR TEXT unique1 TEXT common1 )", "TEXT common1" },
	{ "( OR TEXT common1 TEXT common2 ) ( OR TEXT common1 OR TEXT common2 TEXT unique1 )", "(OR TEXT common1 TEXT common2)" },
	{ "TEXT common1 ( OR TEXT unique1 TEXT common1 ) ( OR TEXT unique3 TEXT common1 )", "TEXT common1" },
	{ "OR ( TEXT common1 ( OR TEXT unique1 TEXT common1 ) ) TEXT unique1", "(OR TEXT common1 TEXT unique1)" },

	/* SUB: extract common OR */
	{ "( OR TEXT common1 TEXT unique1 ) ( OR TEXT common1 TEXT unique2 )", "(OR (TEXT unique1 TEXT unique2) TEXT common1)" },
	{ "( OR TEXT unique1 TEXT common1 ) ( OR TEXT unique2 TEXT common1 )", "(OR (TEXT unique1 TEXT unique2) TEXT common1)" },
	{ "( OR TEXT common1 TEXT unique1 ) ( OR TEXT unique2 TEXT common1 )", "(OR (TEXT unique1 TEXT unique2) TEXT common1)" },
	{ "( OR TEXT unique1 TEXT common1 ) ( OR TEXT common1 TEXT unique2 )", "(OR (TEXT unique1 TEXT unique2) TEXT common1)" },

	{ "( OR TEXT unique1 TEXT common1 ) ( OR TEXT common1 OR TEXT unique2 TEXT unique3 )", "(OR (TEXT unique1 (OR TEXT unique2 TEXT unique3)) TEXT common1)" },
	{ "( OR TEXT common1 OR TEXT common2 TEXT unique1 ) ( OR TEXT common1 OR TEXT common2 TEXT unique2 )", "(OR (TEXT unique1 TEXT unique2) OR TEXT common2 TEXT common1)" },
	{ "( OR TEXT common1 OR TEXT common2 OR TEXT unique1 TEXT unique2 ) ( OR TEXT common1 OR TEXT common2 OR TEXT unique3 TEXT unique4 )", "(OR ((OR TEXT unique1 TEXT unique2) (OR TEXT unique3 TEXT unique4)) OR TEXT common2 TEXT common1)" },

	/* non-matching cases */
	{ "( OR TEXT unique1 TEXT unique2 ) TEXT unique3", "(OR TEXT unique1 TEXT unique2) TEXT unique3" },
	{ "( OR TEXT unique1 TEXT unique2 ) ( OR TEXT unique3 TEXT unique4 )", "(OR TEXT unique1 TEXT unique2) (OR TEXT unique3 TEXT unique4)" },
	{ "( OR TEXT common1 TEXT unique1 ) ( OR TEXT common1 TEXT unique2 ) TEXT unique3", "(OR TEXT common1 TEXT unique1) (OR TEXT common1 TEXT unique2) TEXT unique3" },
	{ "( OR TEXT common1 TEXT unique1 ) ( OR TEXT common1 TEXT common2 ) ( OR TEXT common2 TEXT unique2 )", "(OR TEXT common1 TEXT unique1) (OR TEXT common1 TEXT common2) (OR TEXT common2 TEXT unique2)" },
};

static struct mail_search_args *
test_build_search_args(const char *args)
{
	struct mail_search_parser *parser;
	struct mail_search_args *sargs;
	const char *error, *charset = "UTF-8";

	parser = mail_search_parser_init_cmdline(t_strsplit(args, " "));
	if (mail_search_build(mail_search_register_get_imap(),
			      parser, &charset, &sargs, &error) < 0)
		i_panic("%s", error);
	mail_search_parser_deinit(&parser);
	return sargs;
}

static void test_mail_search_args_simplify(void)
{
	struct mail_search_args *args;
	string_t *str = t_str_new(256);
	const char *error;
	unsigned int i;

	test_begin("mail search args simplify");
	for (i = 0; i < N_ELEMENTS(tests); i++) {
		args = test_build_search_args(tests[i].input);
		mail_search_args_simplify(args);

		str_truncate(str, 0);
		test_assert(mail_search_args_to_imap(str, args->args, &error));
		test_assert_idx(strcmp(str_c(str), tests[i].output) == 0, i);
		mail_search_args_unref(&args);
	}
	test_end();
}

static void test_mail_search_args_simplify_empty_lists(void)
{
	struct mail_search_args *args;

	test_begin("mail search args simplify empty args");

	args = mail_search_build_init();
	mail_search_args_simplify(args);
	mail_search_args_unref(&args);

	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_mail_search_args_simplify,
		test_mail_search_args_simplify_empty_lists,
		NULL
	};

	return test_run(test_functions);
}
