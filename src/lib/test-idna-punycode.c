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

static void cp_str_to_ucs4(const char *input, ARRAY_TYPE(unichars) *output)
{
	const char *p = input, *pend = input + strlen(input);
	int ret;

	while (p < pend) {
		i_assert((pend - p) >= 6);
		i_assert(*p == 'U' || *p == 'u');
		p++;
		i_assert(*p == '+');
		p++;

		char hex[5] = { p[0], p[1], p[2], p[3], '\0' };
		uint32_t cp;

		ret = str_to_uint32_hex(hex, &cp);
		i_assert(ret == 0);
		p += 4;
		array_push_back(output, &cp);

		if (p == pend)
			break;
		i_assert(*p == ' ');
		p++;
	}
}

static void test_idna_punycode_examples(void)
{
	/* RFC 3492, Section 7.1 */

	static struct test_case {
		const char *uni;
		const char *puny;
		bool no_decode;
	} test_cases[] = {
		/* (A) Arabic (Egyptian): */
		{
			.uni =  "u+0644 u+064A u+0647 u+0645 u+0627 u+0628 "
				"u+062A u+0643 u+0644 u+0645 u+0648 u+0634 "
				"u+0639 u+0631 u+0628 u+064A u+061F",
			.puny = "egbpdaj6bu4bxfgehfvwxn",
		},
		/* (B) Chinese (simplified): */
		{
			.uni =  "u+4ED6 u+4EEC u+4E3A u+4EC0 u+4E48 u+4E0D "
				"u+8BF4 u+4E2D u+6587",
			.puny = "ihqwcrb4cv8a8dqg056pqjye",
		},
		/* (C) Chinese (traditional): */
		{
			.uni =  "u+4ED6 u+5011 u+7232 u+4EC0 u+9EBD u+4E0D "
				"u+8AAA u+4E2D u+6587",
			.puny = "ihqwctvzc91f659drss3x8bo0yb",
		},
		/* (D) Czech:
		   Pro<ccaron>prost<ecaron>nemluv<iacute><ccaron>esky */
		{
			.uni =  "U+0050 u+0072 u+006F u+010D u+0070 u+0072 "
				"u+006F u+0073 u+0074 u+011B u+006E u+0065 "
				"u+006D u+006C u+0075 u+0076 u+00ED u+010D "
				"u+0065 u+0073 u+006B u+0079",
			.puny = "Proprostnemluvesky-uyb24dma41a",
		},
		/* (E) Hebrew: */
		{
			.uni =  "u+05DC u+05DE u+05D4 u+05D4 u+05DD u+05E4 "
				"u+05E9 u+05D5 u+05D8 u+05DC u+05D0 u+05DE "
				"u+05D3 u+05D1 u+05E8 u+05D9 u+05DD u+05E2 "
				"u+05D1 u+05E8 u+05D9 u+05EA",
			.puny = "4dbcagdahymbxekheh6e0a7fei0b",
		},
		/* (F) Hindi (Devanagari): */
		{
			.uni =  "u+092F u+0939 u+0932 u+094B u+0917 u+0939 "
				"u+093F u+0928 u+094D u+0926 u+0940 u+0915 "
				"u+094D u+092F u+094B u+0902 u+0928 u+0939 "
				"u+0940 u+0902 u+092C u+094B u+0932 u+0938 "
				"u+0915 u+0924 u+0947 u+0939 u+0948 u+0902 ",
			.puny = "i1baa7eci9glrd9b2ae1bj0hfcgg6iyaf8o0a1dig0cd",
		},
		/* (G) Japanese (kanji and hiragana): */
		{
			.uni =  "u+306A u+305C u+307F u+3093 u+306A u+65E5 "
				"u+672C u+8A9E u+3092 u+8A71 u+3057 u+3066 "
				"u+304F u+308C u+306A u+3044 u+306E u+304B",
			.puny = "n8jok5ay5dzabd5bym9f0cm5685rrjetr6pdxa",
		},
		/* (H) Korean (Hangul syllables): */
		{
			.uni =  "u+C138 u+ACC4 u+C758 u+BAA8 u+B4E0 u+C0AC "
				"u+B78C u+B4E4 u+C774 u+D55C u+AD6D u+C5B4 "
				"u+B97C u+C774 u+D574 u+D55C u+B2E4 u+BA74 "
				"u+C5BC u+B9C8 u+B098 u+C88B u+C744 u+AE4C ",
			.puny = "989aomsvi5e83db1d2a355cv1e0vak1dwrv93d5xbh15a"
				"0dt30a5jpsd879ccm6fea98c",
		},
		/* (I) Russian (Cyrillic): (+erratum #3026) */
		{
			.uni =  "U+043F u+043E u+0447 u+0435 u+043C u+0443 "
				"u+0436 u+0435 u+043E u+043D u+0438 u+043D "
				"u+0435 u+0433 u+043E u+0432 u+043E u+0440 "
				"u+044F u+0442 u+043F u+043E u+0440 u+0443 "
				"u+0441 u+0441 u+043A u+0438",
			.puny = "b1abfaaepdrnnbgefbadotcwatmq2g4l",
		},
		/* (J) Spanish:
		   Porqu<eacute>nopuedensimplementehablarenEspa<ntilde>ol */
		{
			.uni =  "U+0050 u+006F u+0072 u+0071 u+0075 u+00E9 "
				"u+006E u+006F u+0070 u+0075 u+0065 u+0064 "
				"u+0065 u+006E u+0073 u+0069 u+006D u+0070 "
				"u+006C u+0065 u+006D u+0065 u+006E u+0074 "
				"u+0065 u+0068 u+0061 u+0062 u+006C u+0061 "
				"u+0072 u+0065 u+006E U+0045 u+0073 u+0070 "
				"u+0061 u+00F1 u+006F u+006C",
			.puny = "PorqunopuedensimplementehablarenEspaol-fmd56a",
		},
		/* (K) Vietnamese:
		   T<adotbelow>isaoh<odotbelow>kh<ocirc>ngth<ecirchookabove>ch\
		   <ihookabove>n<oacute>iti<ecircacute>ngVi<ecircdotbelow>t */
		{
			.uni =  "U+0054 u+1EA1 u+0069 u+0073 u+0061 u+006F "
				"u+0068 u+1ECD u+006B u+0068 u+00F4 u+006E "
				"u+0067 u+0074 u+0068 u+1EC3 u+0063 u+0068 "
				"u+1EC9 u+006E u+00F3 u+0069 u+0074 u+0069 "
				"u+1EBF u+006E u+0067 U+0056 u+0069 u+1EC7 "
				"u+0074",
			.puny = "TisaohkhngthchnitingVit-kjcr8268qyxafd2f1b9g",
		},
		/* (L) 3<nen>B<gumi><kinpachi><sensei> */
		{
			.uni =  "u+0033 u+5E74 U+0042 u+7D44 u+91D1 u+516B "
				"u+5148 u+751F",
			.puny = "3B-ww4c5e180e575a65lsy2b",
		},
		/* (M) <amuro><namie>-with-SUPER-MONKEYS */
		{
			.uni =  "u+5B89 u+5BA4 u+5948 u+7F8E u+6075 u+002D "
				"u+0077 u+0069 u+0074 u+0068 u+002D U+0053 "
				"U+0055 U+0050 U+0045 U+0052 u+002D U+004D "
				"U+004F U+004E U+004B U+0045 U+0059 U+0053",
			.puny = "-with-SUPER-MONKEYS-pc58ag80a8qai00g7n9n",
		},
		/* (N) Hello-Another-Way-<sorezore><no><basho> */
		{
			.uni =  "U+0048 u+0065 u+006C u+006C u+006F u+002D "
				"U+0041 u+006E u+006F u+0074 u+0068 u+0065 "
				"u+0072 u+002D U+0057 u+0061 u+0079 u+002D "
				"u+305D u+308C u+305E u+308C u+306E u+5834 "
				"u+6240",
			.puny = "Hello-Another-Way--fc4qua05auwb3674vfr0b",
		},
		/* (O) <hitotsu><yane><no><shita>2 */
		{
			.uni =  "u+3072 u+3068 u+3064 u+5C4B u+6839 u+306E "
				"u+4E0B u+0032",
			.puny = "2-u9tlzr9756bt3uc0v",
		},
		/* (P) Maji<de>Koi<suru>5<byou><mae> */
		{
			.uni =  "U+004D u+0061 u+006A u+0069 u+3067 U+004B "
				"u+006F u+0069 u+3059 u+308B u+0035 u+79D2 "
				"u+524D",
			.puny = "MajiKoi5-783gue6qz075azm5e",
		},
		/* (Q) <pafii>de<runba> */
		{
			.uni =  "u+30D1 u+30D5 u+30A3 u+30FC u+0064 u+0065 "
				"u+30EB u+30F3 u+30D0",
			.puny = "de-jg4avhby1noc0d",
		},
		/* (R) <sono><supiido><de> */
		{
			.uni =  "u+305D u+306E u+30B9 u+30D4 u+30FC u+30C9 "
				"u+3067",
			.puny = "d9juau41awczczp",
		},
		/* (S) -> $1.00 <- */
		{
			.uni =  "u+002D u+003E u+0020 u+0024 u+0031 u+002E "
				"u+0030 u+0030 u+0020 u+003C u+002D",
			.puny = "-> $1.00 <--",
			.no_decode = TRUE,
		},
	};

	ARRAY_TYPE(unichars) uni_ucs4, puny_ucs4;
	uint32_t r[LABEL_BUF_SIZE];
	unsigned int i;

	t_array_init(&uni_ucs4, LABEL_BUF_SIZE);
	t_array_init(&puny_ucs4, LABEL_BUF_SIZE);

	test_begin("idna - punycode examples");
	for (i = 0; i < N_ELEMENTS(test_cases); i ++) {
		const uint32_t *uni, *puny;
		unsigned int uni_count, puny_count;
		int ret;

		array_clear(&uni_ucs4);
		array_clear(&puny_ucs4);
		cp_str_to_ucs4(test_cases[i].uni, &uni_ucs4);
		ret = uni_utf8_to_ucs4(test_cases[i].puny, &puny_ucs4);
		i_assert(ret == 0);

		uni = array_get(&uni_ucs4, &uni_count);
		puny = array_get(&puny_ucs4, &puny_count);

		/* encode */
		ret = idna_punycode_encode(uni, uni_count, r, N_ELEMENTS(r));
		test_assert_idx(ret >= 0, i);
		if (ret >= 0) {
			test_assert_memcmp_idx(
				r, ret * sizeof(uint32_t),
				puny, puny_count * sizeof(uint32_t), i);
		}

		/* decode */
		if (test_cases[i].no_decode)
			continue;
		ret = idna_punycode_decode(puny, puny_count, r, N_ELEMENTS(r));
		test_assert_idx(ret >= 0, i);
		if (ret >= 0) {
			test_assert_memcmp_idx(
				r, ret * sizeof(uint32_t),
				uni, uni_count * sizeof(uint32_t), i);
		}
	}
	test_end();
}

void test_idna_punycode(void)
{
	test_idna_punycode_decode();
	test_idna_punycode_decode_len_boundary();
	test_idna_punycode_decode_invalid_codepoint();
	test_idna_punycode_examples();
}
