/* Copyright (c) 2009-2011 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "str.h"
#include "strescape.h"

struct strinput {
	const char *input;
	const char *output;
};

void test_strescape(void)
{
	static struct strinput unesc[] = {
		{ "foo", "foo" },
		{ "\\\\\\\\\\\"\\\"\\\'\\\'", "\\\\\"\"\'\'" },
		{ "\\a\\n\\r\\", "anr" }
	};
	static struct strinput tabesc[] = {
		{ "foo", "foo" },
		{ "\001", "\0011" },
		{ "\t", "\001t" },
		{ "\r", "\001r" },
		{ "\n", "\001n" },
		{ "\001\001\t\t\r\r\n\n", "\0011\0011\001t\001t\001r\001r\001n\001n" }
	};
	unsigned char buf[1 << CHAR_BIT];
	const char *escaped, *tabstr;
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

	test_begin("str_tabescape");
	for (i = 0; i < N_ELEMENTS(tabesc); i++) {
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
