/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "test-lib.h"
#include "unichar.h"
#include "str.h"

static void test_str_append(void)
{
	string_t *str = t_str_new(32);
	string_t *str2 = t_str_new(32);

	test_begin("str_append_*()");
	str_append(str, "foo");
	str_append_c(str, '|');
	str_append_c(str, '\0');
	test_assert(str->used == 5 && memcmp(str_data(str), "foo|\0", 5) == 0);

	str_append(str2, "sec");
	str_append_c(str2, '\0');
	str_append(str2, "ond");
	str_append_str(str, str2);
	test_assert(str->used == 5+7 && memcmp(str_data(str), "foo|\0sec\0ond", 5+7) == 0);

	test_end();
}

static void test_str_c(void)
{
	string_t *str;
	unsigned int i, j;

	test_begin("str_c()");
	str = t_str_new(0);
	T_BEGIN {
		(void)str_c(str);
	} T_END;

	for (i = 0; i < 32; i++) T_BEGIN {
		str = t_str_new(15);
		for (j = 0; j < i; j++)
			str_append_c(str, 'x');
		T_BEGIN {
			(void)str_c(str);
		} T_END;
	} T_END;
	test_end();
}

static void test_str_insert(void)
{
	string_t *str = t_str_new(32);

	test_begin("str_insert()");
	str_insert(str, 0, "foo");
	str_insert(str, 3, ">");
	str_insert(str, 3, "bar");
	str_insert(str, 0, "<");
	test_assert(str->used == 8 && memcmp(str_data(str), "<foobar>", 8) == 0);

	str_insert(str, 10, "!");
	test_assert(str->used == 11 && memcmp(str_data(str), "<foobar>\0\0!", 11) == 0);

	test_end();
}

static void test_str_delete(void)
{
	string_t *str = t_str_new(32);

	test_begin("str_delete()");
	str_delete(str, 0, 100);
	str_append(str, "123456");
	str_delete(str, 0, 1);
	str_delete(str, 4, 1);
	str_delete(str, 1, 1);
	test_assert(str->used == 3 && memcmp(str_data(str), "245", 3) == 0);

	str_delete(str, 1, 2);
	test_assert(str->used == 1 && memcmp(str_data(str), "2", 1) == 0);

	str_append(str, "bar");
	str_delete(str, 1, 100);
	test_assert(str->used == 1 && memcmp(str_data(str), "2", 1) == 0);

	test_end();
}

static void test_str_append_max(void)
{
	string_t *str = t_str_new(32);

	test_begin("str_append_max()");
	str_append_max(str, "foo", 0);
	test_assert(str->used == 0);

	str_append_max(str, "\0foo", 4);
	test_assert(str->used == 0);

	str_append_max(str, "foo", 3);
	test_assert(str->used == 3 && memcmp(str_data(str), "foo", 3) == 0);
	str_truncate(str, 0);

	str_append_max(str, "foo", 2);
	test_assert(str->used == 2 && memcmp(str_data(str), "fo", 2) == 0);
	str_truncate(str, 0);

	str_append_max(str, "foo\0bar", 7);
	test_assert(str->used == 3 && memcmp(str_data(str), "foo", 3) == 0);
	str_truncate(str, 0);
	test_end();
}

static bool test_str_is_ctrl(char ch)
{
	return (unsigned char)ch <= 0x1f || ch == 0x7f;
}

static bool test_str_is_upper(char ch)
{
	return ch >= 'A' && ch <= 'Z';
}

static bool test_str_is_high(char ch)
{
	return (unsigned char)ch >= 0x80;
}

static void test_str_append_ctrl_escaped(void)
{
	string_t *str = t_str_new(64);

	test_begin("str_append_ctrl_escaped()");

	/* empty input appends nothing */
	str_append_ctrl_escaped(str, "", test_str_is_ctrl);
	test_assert(str_len(str) == 0);

	/* nothing to escape: copied verbatim */
	str_append_ctrl_escaped(str, "plain text", test_str_is_ctrl);
	test_assert_strcmp(str_c(str), "plain text");
	str_truncate(str, 0);

	/* appends after existing content */
	str_append(str, "pre:");
	str_append_ctrl_escaped(str, "a\nb", test_str_is_ctrl);
	test_assert_strcmp(str_c(str), "pre:a<0x0A>b");
	str_truncate(str, 0);

	/* SOH, CR, LF, ESC, TAB, DEL, all escaped as <0xNN> */
	str_append_ctrl_escaped(str, "\001\r\n\033\t\177", test_str_is_ctrl);
	test_assert_strcmp(str_c(str),
			   "<0x01><0x0D><0x0A><0x1B><0x09><0x7F>");
	str_truncate(str, 0);

	/* bytes >= 0x80 are not control characters and are kept */
	str_append_ctrl_escaped(str, "\x80\xff", test_str_is_ctrl);
	test_assert_strcmp(str_c(str), "\x80\xff");
	str_truncate(str, 0);

	/* a flagged byte >= 0x80 is printed as one byte, not sign-extended */
	str_append_ctrl_escaped(str, "\x80\xff", test_str_is_high);
	test_assert_strcmp(str_c(str), "<0x80><0xFF>");
	str_truncate(str, 0);

	/* predicate decides what is unsafe, not the function */
	str_append_ctrl_escaped(str, "aBc\nD", test_str_is_upper);
	test_assert_strcmp(str_c(str), "a<0x42>c\n<0x44>");
	str_truncate(str, 0);

	/* log variant: SOH, CR, LF, ESC, DEL escaped; TAB kept */
	str_append_log_escaped(str, "a\001\r\n\033\t\177b");
	test_assert_strcmp(str_c(str),
			   "a<0x01><0x0D><0x0A><0x1B>\t<0x7F>b");
	str_truncate(str, 0);

	test_end();
}

static void test_str_truncate(void)
{
	string_t *str = t_str_new(8);
	int i;

	test_begin("str_truncate()");
	str_append(str, "123456");
	for (i = 100; i >= 6; i--) {
		str_truncate(str, i);
		test_assert_idx(str_len(str) == 6, i);
	}
	for (; i >= 0; i--) {
		str_truncate(str, i);
		test_assert_idx(str_len(str) == (unsigned int)i, i);
	}
	test_end();
}

static void test_str_truncate_utf8(void)
{
	string_t *str = t_str_new(8);
	int i;

	test_begin("str_truncate_utf8()");
	str_append(str, "123456");
	for (i = 100; i >= 6; i--) {
		str_truncate_utf8(str, i);
		test_assert_idx(str_len(str) == 6, i);
	}
	for (; i >= 0; i--) {
		str_truncate_utf8(str, i);
		test_assert_idx(str_len(str) == (unsigned int)i, i);
	}

	str_append(str, "\xE4\xB8\x80\xE4\xBa\x8C\xE4\xB8\x89"
			"\xE5\x9b\x9b\xE4\xBa\x94\xE5\x85\xAD");
	for (i = 100; i >= 18; i--) {
		str_truncate_utf8(str, i);
		test_assert_idx(str_len(str) == 18, i);
	}
	for (; i >= 0; i--) {
		str_truncate_utf8(str, i);
		test_assert_idx(str_len(str) % 3 == 0, i);
		test_assert_idx((str_len(str) / 3) == ((unsigned int)i / 3), i);
	}

	str_append(str, "\xE4\xB8\x80""1""\xE4\xBa\x8C""2""\xE4\xB8\x89""3"
			"\xE5\x9b\x9b""4""\xE4\xBa\x94""5""\xE5\x85\xAD""6");
	for (i = 100; i >= 24; i--) {
		str_truncate_utf8(str, i);
		test_assert_idx(str_len(str) == 24, i);
	}
	for (; i >= 0; i--) {
		str_truncate_utf8(str, i);
		test_assert_idx(uni_utf8_data_is_valid(str_data(str),
						       str_len(str)), i);
	}
	test_end();
}

void test_str(void)
{
	test_str_append();
	test_str_c();
	test_str_insert();
	test_str_delete();
	test_str_append_max();
	test_str_append_ctrl_escaped();
	test_str_truncate();
	test_str_truncate_utf8();
}
