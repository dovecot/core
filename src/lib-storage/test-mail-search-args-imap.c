/* Copyright (c) 2015-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "str.h"
#include "test-common.h"
#include "mail-search-build.h"
#include "mail-search-parser.h"
#include "mail-search.h"

#define CURRENT_UNIX_TIME 1000000

static struct {
	const char *input, *output;
} tests[] = {
	{ "ALL", NULL },
	{ "1,5:6,10:15", NULL },
	{ "UID 1,5:6,10:15", NULL },
	{ "ANSWERED FLAGGED DELETED SEEN DRAFT RECENT",
	  "(ANSWERED) (FLAGGED) (DELETED) (SEEN) (DRAFT) (RECENT)" },
	{ "KEYWORD foo KEYWORD bar", NULL },
	{ "BEFORE 20-May-2015", "BEFORE \"20-May-2015\"" },
	{ "ON 20-May-2015", "ON \"20-May-2015\"" },
	{ "SINCE 20-May-2015", "SINCE \"20-May-2015\"" },
	{ "SENTBEFORE 20-May-2015", "SENTBEFORE \"20-May-2015\"" },
	{ "SENTON 20-May-2015", "SENTON \"20-May-2015\"" },
	{ "SENTSINCE 20-May-2015", "SENTSINCE \"20-May-2015\"" },
	{ "X-SAVEDBEFORE 20-May-2015", "X-SAVEDBEFORE \"20-May-2015\"" },
	{ "X-SAVEDON 20-May-2015", "X-SAVEDON \"20-May-2015\"" },
	{ "X-SAVEDSINCE 20-May-2015", "X-SAVEDSINCE \"20-May-2015\"" },
	{ "OLDER 1", NULL },
	{ "OLDER 1000", NULL },
	{ "YOUNGER 1", NULL },
	{ "YOUNGER 1000", NULL },
	{ "SMALLER 0", NULL },
	{ "SMALLER 1", NULL },
	{ "SMALLER 4294967295", NULL },
	{ "LARGER 0", NULL },
	{ "LARGER 1", NULL },
	{ "LARGER 4294967295", NULL },
	{ "FROM foo", NULL },
	{ "TO foo", NULL },
	{ "CC foo", NULL },
	{ "BCC foo", NULL },
	{ "SUBJECT foo", NULL },
	{ "HEADER subjecT foo", "SUBJECT foo" },
	{ "HEADER subjecT2 foo", "HEADER SUBJECT2 foo" },
	{ "BODY foo", NULL },
	{ "TEXT foo", NULL },
	{ "MODSEQ 0", NULL },
	{ "MODSEQ 1", NULL },
	{ "MODSEQ 18446744073709551615", NULL },
	{ "MODSEQ /flags/keyword all 0", NULL },
	{ "MODSEQ /flags/\\Seen all 0", NULL },
	{ "MODSEQ /flags/\\Seen priv 0", NULL },
	{ "MODSEQ /flags/\\Seen shared 0", NULL },
	{ "INTHREAD REFERENCES seen", "INTHREAD REFERENCES ((SEEN))" },
	{ "INTHREAD ORDEREDSUBJECT seen", "INTHREAD ORDEREDSUBJECT ((SEEN))" },
	{ "INTHREAD REFS seen", "INTHREAD REFS ((SEEN))" },
	{ "INTHREAD REFS ( OR text foo OR keyword bar seen )",
	  "INTHREAD REFS (((OR TEXT foo OR KEYWORD bar (SEEN))))" },
	{ "X-GUID foo", NULL },
	{ "X-MAILBOX foo", NULL },
	{ "X-REAL-UID 1,5:6,10:15", NULL }
};

static struct mail_search_arg test_failures[] = {
	{ .type = SEARCH_MAILBOX },
	{ .type = SEARCH_MAILBOX_GUID },
	{ .type = SEARCH_BEFORE, .value = {
		  .date_type = MAIL_SEARCH_DATE_TYPE_SENT, .time = 86400-1 } },
	{ .type = SEARCH_ON, .value = {
		  .date_type = MAIL_SEARCH_DATE_TYPE_SENT, .time = 86400-1 } },
	{ .type = SEARCH_SINCE, .value = {
		  .date_type = MAIL_SEARCH_DATE_TYPE_SENT, .time = 86400-1 } },
	{ .type = SEARCH_ON, .value = {
		  .date_type = MAIL_SEARCH_DATE_TYPE_RECEIVED, .time = 86400-1 } },
	{ .type = SEARCH_BEFORE, .value = {
		  .date_type = MAIL_SEARCH_DATE_TYPE_SAVED, .time = 86400-1 } },
	{ .type = SEARCH_ON, .value = {
		  .date_type = MAIL_SEARCH_DATE_TYPE_SAVED, .time = 86400-1 } },
	{ .type = SEARCH_SINCE, .value = {
		  .date_type = MAIL_SEARCH_DATE_TYPE_SAVED, .time = 86400-1 } }
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

static void test_mail_search_args_imap(void)
{
	struct mail_search_args *args;
	string_t *str = t_str_new(256);
	const char *output, *error;
	unsigned int i;

	ioloop_time = CURRENT_UNIX_TIME; /* YOUNGER/OLDER tests need this */

	test_begin("mail search args imap");
	for (i = 0; i < N_ELEMENTS(tests); i++) {
		args = test_build_search_args(tests[i].input);
		output = tests[i].output != NULL ?
			tests[i].output : tests[i].input;
		str_truncate(str, 0);
		test_assert_idx(mail_search_args_to_imap(str, args->args, &error), i);
		test_assert_idx(strcmp(str_c(str), output) == 0, i);
		mail_search_args_unref(&args);
	}
	for (i = 0; i < N_ELEMENTS(test_failures); i++)
		test_assert_idx(!mail_search_args_to_imap(str, &test_failures[i], &error), i);
	test_end();
}

int main(void)
{
	static void (*test_functions[])(void) = {
		test_mail_search_args_imap,
		NULL
	};

	return test_run(test_functions);
}
