/* Copyright (c) 2024 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "punycode.h"
#include "str.h"

static void test_punycode_decode(void)
{
	const struct test_case {
		const char *in;
		const char *out;
		int ret;
	} cases[] = {
		/* has ASCII, appends */
		{ .in = "gr-zia", .out = "\x67\x72\xc3\xa5", .ret = 0 },
		/* has ASCII, inserts */
		{ .in = "bl-yia", .out = "\x62\xc3\xa5\x6c", .ret = 0 },
		/* has ASCII, inserts AND appends */
		{ .in = "stlbl-nrad",
		  .out = "\x73\x74\xc3\xa5\x6c\x62\x6c\xc3\xa5", .ret = 0 },
		/* has no ASCII, appends */
		{ .in = "--7sbabjsrp6aymef",
		  .out = "\xd0\xb0\xd0\xba\xd1\x82\xd1\x80\xd0\xb8\xd1\x81\xd0"
			 "\xb0\x2d\xd0\xb2\xd0\xb5\xd1\x81\xd0\xbd\xd0\xb0",
		  .ret = 0 },
		/* broken */
		{ .in = "zz-zzzz", .out = "", .ret = -1 },
	};

	unsigned int i;
	string_t *r = t_str_new(42);

	test_begin("punycode decoding");
	for (i = 0; i < N_ELEMENTS(cases); i ++) {
		str_truncate(r, 0);
		int ret = punycode_decode(cases[i].in, strlen(cases[i].in), r);
		test_assert_idx(ret == cases[i].ret, i);
		test_assert_strcmp_idx(str_c(r), cases[i].out, i);
	}
	test_end();
}

void test_punycode(void)
{
	test_punycode_decode();
}
