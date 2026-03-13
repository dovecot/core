/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "test-lib.h"
#include "str.h"
#include "idna-punycode.h"

static void test_idna_punycode_decode(void)
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
		{ .in = "gr-zi", .out = "", .ret = -1 },
		{ .in = "zz-zzzz", .out = "", .ret = -1 },
		{ .in = "zz-", .out = "", .ret = -1 },
		{ .in = "", .out = "", .ret = -1 },
	};

	unsigned int i;
	string_t *r = t_str_new(42);

	test_begin("punycode decoding");
	for (i = 0; i < N_ELEMENTS(cases); i ++) {
		str_truncate(r, 0);
		int ret = idna_punycode_decode_utf8(
			(const unsigned char *)cases[i].in, strlen(cases[i].in),
			r);
		test_assert_idx(ret == cases[i].ret, i);
		test_assert_strcmp_idx(str_c(r), cases[i].out, i);
	}
	test_end();
}

static void test_idna_punycode_decode_len_boundary(void)
{
	/* punycode_decode() must honor len and not scan past it.
	   rfc822_decode_punycode() calls it with input pointing into a longer
	   NUL-terminated dot-atom buffer and len equal to a single label's
	   length, so a '-' in a later label lies past the len boundary. Decoding
	   the "a" label of "a.b-c" (len=1) must not read the '-' at offset 3 nor
	   abort. */
	string_t *r = t_str_new(42);
	const char *buf = "a.b-c"; /* NUL-terminated; '-' is at offset 3 */

	test_begin("punycode decoding len boundary");
	int ret = idna_punycode_decode_utf8((const unsigned char *)buf, 1, r);
	test_assert(ret == -1 || ret == 0);
	test_end();
}

static void test_idna_punycode_decode_invalid_codepoint(void)
{
	/* A punycoded label can reconstruct a code point that is not a valid
	   Unicode scalar value (a surrogate 0xD800..0xDFFF or a value above
	   U+10FFFF). Such input must be rejected with -1 rather than reaching
	   the uni_ucs4_to_utf8() sink, which would i_assert(uni_is_valid_ucs4())
	   and i_panic(). These inputs decode (with no basic code points, so
	   out=0) to n = 0x80 + delta:
	     "ib9b"  -> delta 55168  -> n = 0xD800 (high surrogate)
	     "un32g" -> delta 1114000 -> n = 0x110010 (> U+10FFFF) */
	const char *const inputs[] = { "ib9b", "un32g" };
	string_t *r = t_str_new(42);

	test_begin("punycode decoding invalid codepoint");
	for (unsigned int i = 0; i < N_ELEMENTS(inputs); i++) {
		str_truncate(r, 0);
		int ret = idna_punycode_decode_utf8(
			(const unsigned char *)inputs[i], strlen(inputs[i]), r);
		test_assert_idx(ret == -1, i);
	}
	test_end();
}

void test_idna_punycode(void)
{
	test_idna_punycode_decode();
	test_idna_punycode_decode_len_boundary();
	test_idna_punycode_decode_invalid_codepoint();
}
