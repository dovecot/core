/* Copyright (c) 2007-2013 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "str.h"
#include "buffer.h"
#include "unichar.h"

void test_unichar(void)
{
	static const char overlong_utf8[] = "\xf8\x80\x95\x81\xa1";
	static const char collate_in[] = "\xc3\xbc \xc2\xb3";
	static const char collate_exp[] = "U\xcc\x88 3";
	buffer_t *collate_out;
	unichar_t chr, chr2;
	string_t *str = t_str_new(16);

	test_begin("unichars");
	for (chr = 0; chr <= 0x10ffff; chr++) {
		str_truncate(str, 0);
		uni_ucs4_to_utf8_c(chr, str);
		test_assert(uni_utf8_str_is_valid(str_c(str)));
		test_assert(uni_utf8_get_char(str_c(str), &chr2) > 0);
		test_assert(chr2 == chr);
	}

	collate_out = buffer_create_dynamic(default_pool, 32);
	uni_utf8_to_decomposed_titlecase(collate_in, sizeof(collate_in),
					 collate_out);
	test_assert(!strcmp(collate_out->data, collate_exp));
	buffer_free(&collate_out);

	test_assert(!uni_utf8_str_is_valid(overlong_utf8));
	test_assert(uni_utf8_get_char(overlong_utf8, &chr2) < 0);
	test_end();
}
