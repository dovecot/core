/* Copyright (c) 2009-2018 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "str.h"
#include "strescape.h"

struct strinput {
	const char *input;
	const char *output;
};

static const char tabescaped_input[] = "\0011\001t\001r\001nplip\001n";
static const char tabunescaped_input[] = "\001\t\r\nplip\n";

static const char *wrong_tabescaped_input = "a\001\001b\001\nc\0011\001t\001r\001nplip\001n";
static const char *wrong_tabescaped_output = "a\001b\nc\001\t\r\nplip\n";

static struct {
	const char *input;
	const char *const *output;
} strsplit_tests[] = {
	{ /*tabescaped_input3*/NULL, (const char *const []) {
		tabunescaped_input,
		tabunescaped_input,
		tabunescaped_input,
		"",
		NULL
	} },
	{ "", (const char *const []) { NULL } },
	{ "\t", (const char *const []) { "", "", NULL } },
	{ tabescaped_input, (const char *const []) {
		tabunescaped_input,
		NULL
	} },
};

static void test_str_escape(void)
{
	static const struct strinput unesc[] = {
		{ "foo", "foo" },
		{ "\\\\\\\\\\\"\\\"\\\'\\\'", "\\\\\"\"\'\'" },
		{ "\\a\\n\\r\\", "anr" }
	};
	static const struct strinput tabesc[] = {
		{ "foo", "foo" },
		{ "\001", "\0011" },
		{ "\t", "\001t" },
		{ "\r", "\001r" },
		{ "\n", "\001n" },
		{ "\001\001\t\t\r\r\n\n", "\0011\0011\001t\001t\001r\001r\001n\001n" }
	};
	unsigned char buf[1 << CHAR_BIT];
	const char *escaped, *tabstr, *unesc_str;
	string_t *str;
	unsigned int i;

	test_begin("str_escape");
	for (i = 1; i < sizeof(buf); i++)
		buf[i-1] = i;
	buf[i-1] = '\0';

	escaped = str_escape((char *)buf);
	test_assert(strlen(escaped) == (1 << CHAR_BIT) - 1 + 3);
	test_assert(escaped['\"'-1] == '\\'); /* 34 */
	test_assert(escaped['\"'] == '\"');
	test_assert(escaped['\''+1-1] == '\\'); /* 39 */
	test_assert(escaped['\''+1] == '\'');
	test_assert(escaped['\\'+2-1] == '\\'); /* 92 */
	test_assert(escaped['\\'+2] == '\\');
	test_assert(strcmp(str_escape("\\\\\"\"\'\'"),
			   "\\\\\\\\\\\"\\\"\\\'\\\'") == 0);
	test_end();

	test_begin("str_nescape");

	escaped = str_nescape("\"escape only first but not 'this'", 10);
	test_assert(strcmp(escaped, "\\\"escape on") == 0);

	escaped = str_nescape("\"hello\"\0\"world\"", 15);
	test_assert(memcmp(escaped, "\\\"hello\\\"\0\\\"world\\\"", 19) == 0);

	test_end();

	str = t_str_new(256);
	test_begin("str_unescape");
	for (i = 0; i < N_ELEMENTS(unesc); i++) {
		test_assert(strcmp(str_unescape(t_strdup_noconst(unesc[i].input)),
				   unesc[i].output) == 0);
		str_truncate(str, 0);
		str_append_unescaped(str, unesc[i].input, strlen(unesc[i].input));
		test_assert(strcmp(str_c(str), unesc[i].output) == 0);
	}
	test_end();

	test_begin("str_unescape_next");
	escaped = "foo\"bar\\\"b\\\\az\"plop";
	test_assert(str_unescape_next(&escaped, &unesc_str) == 0);
	test_assert(strcmp(unesc_str, "foo") == 0);
	test_assert(str_unescape_next(&escaped, &unesc_str) == 0);
	test_assert(strcmp(unesc_str, "bar\"b\\az") == 0);
	test_assert(str_unescape_next(&escaped, &unesc_str) == -1);
	escaped = "foo\\";
	test_assert(str_unescape_next(&escaped, &unesc_str) == -1);
	test_end();

	test_begin("str_tabescape");
	for (i = 0; i < N_ELEMENTS(tabesc); i++) {
		test_assert(strcmp(t_str_tabunescape(tabesc[i].output),
				   tabesc[i].input) == 0);
		test_assert(strcmp(str_tabunescape(t_strdup_noconst(tabesc[i].output)),
				   tabesc[i].input) == 0);
		test_assert(strcmp(str_tabescape(tabesc[i].input),
				   tabesc[i].output) == 0);
		str_truncate(str, 0);
		str_append_tabunescaped(str, tabesc[i].output, strlen(tabesc[i].output));
		test_assert(strcmp(str_c(str), tabesc[i].input) == 0);
	}
	str_truncate(str, 0);
	tabstr = "\0012\001l\001";
	str_append_tabunescaped(str, tabstr, strlen(tabstr));
	test_assert(strcmp(str_c(str), "2l") == 0);
	test_assert(strcmp(str_c(str), str_tabunescape(t_strdup_noconst(tabstr))) == 0);
	test_end();
}

static void test_tabescape(void)
{
	string_t *str = t_str_new(128);

	test_begin("string tabescaping");
	test_assert(strcmp(str_tabescape(tabunescaped_input), tabescaped_input) == 0);

	str_append_tabescaped(str, tabunescaped_input);
	test_assert(strcmp(str_c(str), tabescaped_input) == 0);

	/* unescaping */
	str_truncate(str, 0);
	str_append_tabunescaped(str, tabescaped_input, strlen(tabescaped_input));
	test_assert(strcmp(str_c(str), tabunescaped_input) == 0);

	test_assert(strcmp(str_tabunescape(t_strdup_noconst(tabescaped_input)), tabunescaped_input) == 0);
	test_assert(strcmp(t_str_tabunescape(tabescaped_input), tabunescaped_input) == 0);

	/* unescaping with wrongly written tabescape-input */
	str_truncate(str, 0);
	str_append_tabunescaped(str, wrong_tabescaped_input, strlen(wrong_tabescaped_input));
	test_assert(strcmp(str_c(str), wrong_tabescaped_output) == 0);

	test_assert(strcmp(str_tabunescape(t_strdup_noconst(wrong_tabescaped_input)), wrong_tabescaped_output) == 0);
	test_assert(strcmp(t_str_tabunescape(wrong_tabescaped_input), wrong_tabescaped_output) == 0);

	test_end();
}

static void test_strsplit_tabescaped(void)
{
	const char *const *args;

	test_begin("*_strsplit_tabescaped()");
	for (unsigned int i = 0; i < N_ELEMENTS(strsplit_tests); i++) {
		args = t_strsplit_tabescaped(strsplit_tests[i].input);
		for (unsigned int j = 0; strsplit_tests[i].output[j] != NULL; j++)
			test_assert_idx(null_strcmp(strsplit_tests[i].output[j], args[j]) == 0, i);
	}
	test_end();
}

static void test_strsplit_tabescaped_inplace(void)
{
	const char *const *args;

	test_begin("*_strsplit_tabescaped_inplace()");
	for (unsigned int i = 0; i < N_ELEMENTS(strsplit_tests); i++) {
		char *input = t_strdup_noconst(strsplit_tests[i].input);
		args = t_strsplit_tabescaped_inplace(input);
		for (unsigned int j = 0; strsplit_tests[i].output[j] != NULL; j++)
			test_assert_idx(null_strcmp(strsplit_tests[i].output[j], args[j]) == 0, i);
	}
	test_end();
}

void test_strescape(void)
{
	strsplit_tests[0].input = t_strdup_printf("%s\t%s\t%s\t",
		tabescaped_input, tabescaped_input, tabescaped_input);
	test_str_escape();
	test_tabescape();
	test_strsplit_tabescaped();
	test_strsplit_tabescaped_inplace();
}
