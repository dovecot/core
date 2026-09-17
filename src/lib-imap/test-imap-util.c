/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "array.h"
#include "istream.h"
#include "str.h"
#include "mail-types.h"
#include "imap-arg.h"
#include "imap-parser.h"
#include "imap-util.h"
#include "test-common.h"

#include <sys/resource.h>

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

static void test_imap_write_arg(void)
{
	ARRAY_TYPE(imap_arg_list) list_root, list_sub;
	struct imap_arg *arg;

	t_array_init(&list_sub, 2);
	arg = array_append_space(&list_sub);
	arg->type = IMAP_ARG_ATOM;
	arg->_data.str = "foo";
	arg = array_append_space(&list_sub);
	arg->type = IMAP_ARG_EOL;

	t_array_init(&list_root, 2);
	arg = array_append_space(&list_root);
	arg->type = IMAP_ARG_LIST;
	arg->_data.list = list_sub;
	arg = array_append_space(&list_root);
	arg->type = IMAP_ARG_STRING;
	arg->_data.str = "bar";
	arg = array_append_space(&list_root);
	arg->type = IMAP_ARG_EOL;

	const struct {
		struct imap_arg input;
		const char *output;
	} tests[] = {
		{ { .type = IMAP_ARG_NIL }, "NIL" },
		{ { .type = IMAP_ARG_ATOM, ._data.str = "atom" }, "atom" },
		{ { .type = IMAP_ARG_STRING, ._data.str = "s\\t\"ring" }, "\"s\\\\t\\\"ring\"" },
		{ { .type = IMAP_ARG_LITERAL, ._data.str = "l\\i\"t\r\neral" }, "{11}\r\nl\\i\"t\r\neral" },
		{ { .type = IMAP_ARG_LITERAL_SIZE, ._data.literal_size = 12345678 }, "<12345678 byte literal>" },
		{ { .type = IMAP_ARG_LITERAL_SIZE_NONSYNC, ._data.literal_size = 12345678 }, "<12345678 byte literal>" },
		{ { .type = IMAP_ARG_LIST, ._data.list = list_root }, "((foo) \"bar\")" },
	};
	string_t *str = t_str_new(100);

	test_begin("imap_write_arg");
	for (unsigned int i = 0; i < N_ELEMENTS(tests); i++) {
		str_truncate(str, 0);
		imap_write_arg(str, &tests[i].input);
		test_assert_idx(strcmp(str_c(str), tests[i].output) == 0, i);
	}
	test_end();
}

static void
test_imap_write_args_input(const char *input, const char *output,
			   const char *human_output)
{
	struct istream *is;
	struct imap_parser *parser;
	const struct imap_arg *args;
	string_t *str = t_str_new(256);
	const char *line = t_strconcat(input, "\r\n", NULL);

	is = i_stream_create_from_data(line, strlen(line));
	parser = imap_parser_create(is, NULL, SIZE_MAX, NULL);
	(void)i_stream_read(is);
	test_assert(imap_parser_read_args(parser, 0, 0, &args) > 0);

	imap_write_args(str, args);
	test_assert_strcmp(str_c(str), output);

	str_truncate(str, 0);
	imap_write_args_for_human(str, args);
	test_assert_strcmp(str_c(str), human_output);

	imap_parser_unref(&parser);
	i_stream_unref(&is);
}

static void test_imap_write_args(void)
{
	static const struct {
		const char *input;
		const char *output;
		const char *human_output;
	} tests[] = {
		{ "foo", "foo", "foo" },
		{ "foo bar baz", "foo bar baz", "foo bar baz" },
		{ "NIL", "NIL", "NIL" },
		{ "\"foo bar\"", "\"foo bar\"", "\"foo bar\"" },
		{ "\"a\\\\b\\\"c\"", "\"a\\\\b\\\"c\"", "\"a\\\\b\\\"c\"" },
		{ "()", "()", "()" },
		{ "(foo)", "(foo)", "(foo)" },
		{ "(foo bar)", "(foo bar)", "(foo bar)" },
		{ "(())", "(())", "(())" },
		{ "(() ())", "(() ())", "(() ())" },
		{ "(foo) bar", "(foo) bar", "(foo) bar" },
		{ "foo (bar)", "foo (bar)", "foo (bar)" },
		{ "a (b (c d) e) f", "a (b (c d) e) f", "a (b (c d) e) f" },
		{ "(((a b) c) d) e", "(((a b) c) d) e", "(((a b) c) d) e" },
		{ "(a (\"b\" (NIL)))", "(a (\"b\" (NIL)))", "(a (\"b\" (NIL)))" },
		/* lists with more than LIST_INIT_COUNT (7) args get their array
		   reallocated by imap-parser */
		{ "((x)) a b c d e f g h", "((x)) a b c d e f g h",
		  "((x)) a b c d e f g h" },
		{ "(((x)) a b c d e f g h) y", "(((x)) a b c d e f g h) y",
		  "(((x)) a b c d e f g h) y" },
		{ "(a b c d e f g h ((x)) i) y", "(a b c d e f g h ((x)) i) y",
		  "(a b c d e f g h ((x)) i) y" },
		{ "((\"text\" \"plain\" (\"charset\" \"utf-8\") NIL NIL \"7bit\" 10 1 NIL NIL NIL NIL)(\"text\" \"html\" (\"charset\" \"utf-8\") NIL NIL \"7bit\" 20 2 NIL NIL NIL NIL) \"alternative\" (\"boundary\" \"b\") NIL NIL NIL)",
		  "((\"text\" \"plain\" (\"charset\" \"utf-8\") NIL NIL \"7bit\" 10 1 NIL NIL NIL NIL) (\"text\" \"html\" (\"charset\" \"utf-8\") NIL NIL \"7bit\" 20 2 NIL NIL NIL NIL) \"alternative\" (\"boundary\" \"b\") NIL NIL NIL)",
		  "((\"text\" \"plain\" (\"charset\" \"utf-8\") NIL NIL \"7bit\" 10 1 NIL NIL NIL NIL) (\"text\" \"html\" (\"charset\" \"utf-8\") NIL NIL \"7bit\" 20 2 NIL NIL NIL NIL) \"alternative\" (\"boundary\" \"b\") NIL NIL NIL)" },
		/* literals are returned as strings, and the human-readable
		   output hides multi-line, control and non-UTF-8 chars */
		{ "a {3}\r\nfoo b", "a \"foo\" b", "a \"foo\" b" },
		{ "a {4}\r\nx\r\ny b", "a \"x\r\ny\" b",
		  "a <4 byte multi-line literal> b" },
		{ "({3}\r\nx\x01y)", "(\"x\x01y\")", "(\"x?y\")" },
		{ "({3}\r\nx\xffy)", "(\"x\xffy\")", "(\"x\xef\xbf\xbdy\")" },
		{ "\"x\xc3\xa4y\"", "\"x\xc3\xa4y\"", "\"x\xc3\xa4y\"" },
	};

	test_begin("imap_write_args");
	for (unsigned int i = 0; i < N_ELEMENTS(tests); i++) T_BEGIN {
		test_imap_write_args_input(tests[i].input, tests[i].output,
					   tests[i].human_output);
	} T_END;
	test_end();
}

/* Small enough that a recursive writer runs out of stack while writing the
   deeply nested args below. */
#define TEST_STACK_LIMIT (1024*1024)

static bool test_stack_limit_set(struct rlimit *old_r)
{
	struct rlimit rl;

	if (getrlimit(RLIMIT_STACK, old_r) < 0)
		return FALSE;
	if (old_r->rlim_cur != RLIM_INFINITY &&
	    old_r->rlim_cur <= TEST_STACK_LIMIT)
		return FALSE;

	rl = *old_r;
	rl.rlim_cur = TEST_STACK_LIMIT;
	return setrlimit(RLIMIT_STACK, &rl) == 0;
}

static void test_imap_write_args_deep_nesting(void)
{
	/* The list nesting depth is limited only by the IMAP line length, so
	   the args must be written without a stack frame per nesting level.
	   The stack limit is lowered while writing, so a recursive writer
	   crashes here instead of depending on the stack size. */
	const unsigned int depth = 100000;
	string_t *line, *expected, *str;
	struct istream *is;
	struct imap_parser *parser;
	const struct imap_arg *args;
	struct rlimit old_rlimit;
	bool stack_limited;
	unsigned int i;

	test_begin("imap_write_args() deep nesting");
	expected = str_new(default_pool, depth*2 + 16);
	for (i = 0; i < depth; i++)
		str_append_c(expected, '(');
	str_append(expected, "SEEN");
	for (i = 0; i < depth; i++)
		str_append_c(expected, ')');

	line = str_new(default_pool, str_len(expected) + 4);
	str_append_str(line, expected);
	str_append(line, "\r\n");

	is = i_stream_create_from_data(str_data(line), str_len(line));
	parser = imap_parser_create(is, NULL, SIZE_MAX, NULL);
	(void)i_stream_read(is);
	test_assert(imap_parser_read_args(parser, 0, 0, &args) == 1);
	test_assert(args[0].type == IMAP_ARG_LIST);

	str = str_new(default_pool, str_len(expected) + 1);
	stack_limited = test_stack_limit_set(&old_rlimit);
	imap_write_args(str, args);
	test_assert_strcmp(str_c(str), str_c(expected));

	str_truncate(str, 0);
	imap_write_arg(str, &args[0]);
	test_assert_strcmp(str_c(str), str_c(expected));
	if (stack_limited)
		(void)setrlimit(RLIMIT_STACK, &old_rlimit);

	imap_parser_unref(&parser);
	i_stream_unref(&is);
	str_free(&str);
	str_free(&line);
	str_free(&expected);
	test_end();
}

static void test_imap_write_capabilities(void)
{
	ARRAY_TYPE(const_string) capabilities;
	t_array_init(&capabilities, 5);
	const char *const unsorted_capabilities[] = {
		"foo", "bar", "IMAP4rev1", "baz", "IMAP4rev2", NULL
	};
	array_append(&capabilities, unsorted_capabilities, N_ELEMENTS(unsorted_capabilities));
	string_t *cap_str = t_str_new(256);

	test_begin("imap_write_capabilities");
	imap_write_capability(cap_str, &capabilities);
	test_assert_strcmp(str_c(cap_str), "IMAP4rev1 IMAP4rev2 foo bar baz");
	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_imap_parse_system_flag,
		test_imap_write_arg,
		test_imap_write_args,
		test_imap_write_args_deep_nesting,
		test_imap_write_capabilities,
		NULL
	};
	return test_run(test_functions);
}
