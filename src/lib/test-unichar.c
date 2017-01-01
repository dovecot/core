/* Copyright (c) 2007-2017 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "str.h"
#include "buffer.h"
#include "unichar.h"

static void test_unichar_uni_utf8_strlen(void)
{
	static const char input[] = "\xC3\xA4\xC3\xA4\0a";

	test_begin("uni_utf8_strlen()");
	test_assert(uni_utf8_strlen(input) == 2);
	test_end();

	test_begin("uni_utf8_strlen_n()");
	test_assert(uni_utf8_strlen_n(input, 1) == 0);
	test_assert(uni_utf8_strlen_n(input, 2) == 1);
	test_assert(uni_utf8_strlen_n(input, 3) == 1);
	test_assert(uni_utf8_strlen_n(input, 4) == 2);
	test_end();
}

static void test_unichar_uni_utf8_partial_strlen_n(void)
{
	static const char input[] = "\xC3\xA4\xC3\xA4\0a";
	size_t pos;

	test_begin("uni_utf8_partial_strlen_n()");
	test_assert(uni_utf8_partial_strlen_n(input, 1, &pos) == 0 && pos == 0);
	test_assert(uni_utf8_partial_strlen_n(input, 2, &pos) == 1 && pos == 2);
	test_assert(uni_utf8_partial_strlen_n(input, 3, &pos) == 1 && pos == 2);
	test_assert(uni_utf8_partial_strlen_n(input, 4, &pos) == 2 && pos == 4);
	test_assert(uni_utf8_partial_strlen_n(input, 5, &pos) == 3 && pos == 5);
	test_assert(uni_utf8_partial_strlen_n(input, 6, &pos) == 4 && pos == 6);
	test_end();
}

void test_unichar(void)
{
	static const char overlong_utf8[] = "\xf8\x80\x95\x81\xa1";
	static const char collate_in[] = "\xc3\xbc \xc2\xb3";
	static const char collate_exp[] = "U\xcc\x88 3";
	buffer_t *collate_out;
	unichar_t chr, chr2;
	string_t *str = t_str_new(16);

	test_begin("unichars encode/decode");
	for (chr = 0; chr <= 0x10ffff; chr++) {
		/* The bottom 6 bits should be irrelevant to code coverage,
		   only test 000000, 111111, and something in between. */
		if ((chr & 63) == 1)
			chr += rand() % 62; /* After 0, somewhere between 1 and 62 */
		else if ((chr & 63) > 0 && (chr & 63) < 63)
			chr |= 63; /* After random, straight to 63 */

		str_truncate(str, 0);
		uni_ucs4_to_utf8_c(chr, str);
		test_assert(uni_utf8_str_is_valid(str_c(str)));
		test_assert(uni_utf8_get_char(str_c(str), &chr2) == (int)uni_utf8_char_bytes(*str_data(str)));
		test_assert(chr2 == chr);

		if ((chr & 0x63) == 0) {
			unsigned int utf8len = uni_utf8_char_bytes(*str_c(str));

			/* virtually truncate the byte string */
			while (--utf8len > 0)
				test_assert(uni_utf8_get_char_n(str_c(str), utf8len, &chr2) == 0);

			utf8len = uni_utf8_char_bytes(*str_c(str));

			/* actually truncate the byte stream */
			while (--utf8len > 0) {
				str_truncate(str, utf8len);
				test_assert(!uni_utf8_str_is_valid(str_c(str)));
				test_assert(uni_utf8_get_char(str_c(str), &chr2) == 0);
			}
		}
	}
	test_end();

	test_begin("unichar collation");
	collate_out = buffer_create_dynamic(default_pool, 32);
	uni_utf8_to_decomposed_titlecase(collate_in, sizeof(collate_in),
					 collate_out);
	test_assert(strcmp(collate_out->data, collate_exp) == 0);
	buffer_free(&collate_out);

	test_assert(!uni_utf8_str_is_valid(overlong_utf8));
	test_assert(uni_utf8_get_char(overlong_utf8, &chr2) < 0);
	test_end();

	test_unichar_uni_utf8_strlen();
	test_unichar_uni_utf8_partial_strlen_n();
}
