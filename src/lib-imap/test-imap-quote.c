/* Copyright (c) 2013-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "imap-quote.h"
#include "test-common.h"

static void test_imap_append_string_for_humans(void)
{
	static const struct {
		const char *input, *output;
	} tests[] = {
		{ "", "\"\"" },
		{ " ", "\"\"" },
		{ "  ", "\"\"" },
		{ "\t", "\"\"" },
		{ " \t", "\"\"" },
		{ " \t ", "\"\"" },
		{ " foo", "{3}\r\nfoo" },
		{ "\tfoo", "{3}\r\nfoo" },
		{ "\t \tfoo", "{3}\r\nfoo" },
		{ " foo ", "{3}\r\nfoo" },
		{ " foo  ", "{3}\r\nfoo" },
		{ " foo  \t  \t", "{3}\r\nfoo" },
		{ "hello\"world", "{11}\r\nhello\"world" },
		{ "hello\\world", "{11}\r\nhello\\world" },
		{ "hello\rworld", "{11}\r\nhello world" },
		{ "hello\nworld", "{11}\r\nhello world" },
		{ "hello\r\nworld", "{11}\r\nhello world" },
		{ "hello\r\n  world", "{11}\r\nhello world" },
		{ "hello  \r\n  world", "{11}\r\nhello world" },
	};
	string_t *str = t_str_new(128);
	unsigned int i;

	test_begin("imap_append_string_for_humans()");

	for (i = 0; i < N_ELEMENTS(tests); i++) {
		str_truncate(str, 0);
		imap_append_string_for_humans(str, (const void *)tests[i].input,
					      strlen(tests[i].input));
		test_assert_idx(strcmp(tests[i].output, str_c(str)) == 0, i);
	}
	test_end();
}

static void test_imap_append_astring(void)
{
	static const struct {
		const char *input, *output;
	} tests[] = {
		{ "", "\"\"" },
		{ "NIL", "\"NIL\"" },
		{ "niL", "\"niL\"" },
		{ "ni", "ni" },
		{ "\\", "\"\\\\\"" },
		{ "\\\\", "\"\\\\\\\\\"" },
		{ "\\\\\\", "\"\\\\\\\\\\\\\"" },
		{ "\\\\\\\\", "\"\\\\\\\\\\\\\\\\\"" },
		{ "\\\\\\\\\\", "{5}\r\n\\\\\\\\\\" },
		{ "\\\\\\\\\\\\", "{6}\r\n\\\\\\\\\\\\" },
		{ "\"", "\"\\\"\"" },
		{ "\"\"", "\"\\\"\\\"\"" },
		{ "\"\"\"", "\"\\\"\\\"\\\"\"" },
		{ "\"\"\"\"", "\"\\\"\\\"\\\"\\\"\"" },
		{ "\"\"\"\"\"", "{5}\r\n\"\"\"\"\"" },
		{ "\"\"\"\"\"\"", "{6}\r\n\"\"\"\"\"\"" },
		{ "\r", "{1}\r\n\r" },
		{ "\n", "{1}\r\n\n" },
		{ "\r\n", "{2}\r\n\r\n" },
		{ "\x7f", "\"\x7f\"" },
		{ "\x80", "{1}\r\n\x80" },
		{ "\xff", "{1}\r\n\xff" },
	};
	string_t *str = t_str_new(128);
	unsigned int i;

	test_begin("test_imap_append_astring()");

	for (i = 0; i < N_ELEMENTS(tests); i++) {
		str_truncate(str, 0);
		imap_append_astring(str, tests[i].input);
		test_assert_idx(strcmp(tests[i].output, str_c(str)) == 0, i);
	}
	test_end();
}

static void test_imap_append_nstring(void)
{
	static const struct {
		const char *input, *output;
	} tests[] = {
		{ "", "\"\"" },
		{ NULL, "NIL" },
		{ "NIL", "\"NIL\"" },
		{ "\"America N.\"", "\"\\\"America N.\\\"\"" },
		{ "\"America N.\", \"America S.\"", "\"\\\"America N.\\\", \\\"America S.\\\"\"" },
		{ "\"America N.\", \"America S.\", \"Africa\"", "{36}\r\n\"America N.\", \"America S.\", \"Africa\"" },
		{ "Antarctica\n Australia", "{21}\r\nAntarctica\n Australia" },
		{ "ni", "\"ni\"" }
	};
	string_t *str = t_str_new(128);
	unsigned int i;

	test_begin("test_imap_append_nstring()");

	for (i = 0; i < N_ELEMENTS(tests); i++) {
		str_truncate(str, 0);
		imap_append_nstring(str, tests[i].input);
		test_assert_idx(strcmp(tests[i].output, str_c(str)) == 0, i);
	}
	test_end();
}

static void test_imap_append_nstring_nolf(void)
{
	static const struct {
		const char *input, *output;
	} tests[] = {
		{ "", "\"\"" },
		{ NULL, "NIL" },
		{ "NIL", "\"NIL\"" },
		{ "ni", "\"ni\"" },
		{ "\"NIL\n foo", "\"\\\"NIL foo\"" },
		{ "\"America N.\", \"America S.\", \"Africa\"", "{36}\r\n\"America N.\", \"America S.\", \"Africa\"" },
		{ "foo\nbar", "\"foo bar\"" },
		{ "foo\r\nbar", "\"foo bar\"" },
		{ "foo\rbar", "\"foo bar\"" },
		{ "foo\n  bar", "\"foo  bar\"" },
		{ "foo\r\n  bar", "\"foo  bar\"" },
		{ "foo\r  bar", "\"foo  bar\"" },
		{ "foo\n\tbar", "\"foo\tbar\"" },
		{ "foo\r\n\tbar", "\"foo\tbar\"" },
		{ "foo\r\tbar", "\"foo\tbar\"" },
		{ "foo\n bar", "\"foo bar\"" },
		{ "foo\r\n bar", "\"foo bar\"" },
		{ "foo\r bar", "\"foo bar\"" },
		{ "\nfoo\r bar\r\n", "\" foo bar\"" }
	};
	string_t *str = t_str_new(128);
	unsigned int i;

	test_begin("test_imap_append_nstring_nolf()");

	for (i = 0; i < N_ELEMENTS(tests); i++) {
		str_truncate(str, 0);
		imap_append_nstring_nolf(str, tests[i].input);
		test_assert_idx(strcmp(tests[i].output, str_c(str)) == 0, i);
	}
	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_imap_append_string_for_humans,
		test_imap_append_astring,
		test_imap_append_nstring,
		test_imap_append_nstring_nolf,
		NULL
	};
	return test_run(test_functions);
}
