/* Copyright (c) 2015 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "test-common.h"
#include "mail-search-build.h"
#include "mail-search-parser.h"
#include "mail-search.h"

struct {
	const char *input;
	const char *output;
} tests[] = {
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

	{ "1:5 10:20", "1:5,10:20" },
	{ "1:5 NOT 10:20", "1:5 NOT 10:20" },
	{ "1:5 NOT 10:20 NOT 30:40", "1:5 NOT 10:20 NOT 30:40" },
	{ "OR 1:5 NOT 10:20", "(OR 1:5 NOT 10:20)" },
	{ "OR 1:5 OR NOT 10:20 NOT 30:40", "(OR 1:5 NOT 10:20,30:40)" },

	{ "UID 1:5 UID 10:20", "UID 1:5,10:20" },
	{ "UID 1:5 NOT UID 10:20", "UID 1:5 NOT UID 10:20" },
	{ "UID 1:5 NOT UID 10:20 NOT UID 30:40", "UID 1:5 NOT UID 10:20 NOT UID 30:40" },
	{ "OR UID 1:5 NOT UID 10:20", "(OR UID 1:5 NOT UID 10:20)" },
	{ "OR UID 1:5 OR NOT UID 10:20 NOT UID 30:40", "(OR UID 1:5 NOT UID 10:20,30:40)" },

	{ "1:5 UID 10:20", "1:5 UID 10:20" },
	{ "1:5 NOT UID 10:20", "1:5 NOT UID 10:20" },

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

int main(void)
{
	static void (*test_functions[])(void) = {
		test_mail_search_args_simplify,
		NULL
	};

	return test_run(test_functions);
}
