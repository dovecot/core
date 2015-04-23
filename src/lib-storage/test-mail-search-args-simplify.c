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
	{ "OR NOT ANSWERED OR NOT FLAGGED NOT SEEN", "NOT (ANSWERED FLAGGED SEEN)" }
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
