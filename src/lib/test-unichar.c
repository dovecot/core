/* Copyright (c) 2007-2018 Dovecot authors, see the included COPYING file */

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

static void test_unichar_valid_unicode(void)
{
	struct {
		const char *input;
		bool valid;
		unichar_t expected;
	} test_cases[] = {
		{ "a", TRUE, 'a' },
		{ "\xc3\xb1", TRUE, 0x00F1 }, /* U+00F1 */
		{ "\xc3\x28", FALSE, 0x0 }, /* has invalid 2nd octet */
		{ "\xa0\xa1", FALSE, 0x0 }, /* invalid sequence identifier */
		{ "\xed\xb2\x80", FALSE, 0x0 }, /* UTF-8B */
		{ "\xed\xa0\x80", FALSE, 0x0 }, /* surrogate halves, U+D800 .. */
		{ "\xed\xa0\x80", FALSE, 0x0 },
		{ "\xed\xa1\x80", FALSE, 0x0 },
		{ "\xed\xa2\x80", FALSE, 0x0 },
		{ "\xed\xa3\x80", FALSE, 0x0 },
		{ "\xed\xa4\x80", FALSE, 0x0 },
		{ "\xed\xa5\x80", FALSE, 0x0 },
		{ "\xed\xa6\x80", FALSE, 0x0 },
		{ "\xed\xa7\x80", FALSE, 0x0 },
		{ "\xed\xa8\x80", FALSE, 0x0 },
		{ "\xed\xa9\x80", FALSE, 0x0 },
		{ "\xed\xaa\x80", FALSE, 0x0 },
		{ "\xed\xab\x80", FALSE, 0x0 },
		{ "\xed\xac\x80", FALSE, 0x0 },
		{ "\xed\xad\x80", FALSE, 0x0 },
		{ "\xed\xaf\x80", FALSE, 0x0 },
		{ "\xed\xb0\x80", FALSE, 0x0 },
		{ "\xed\xb1\x80", FALSE, 0x0 },
		{ "\xed\xb2\x80", FALSE, 0x0 },
		{ "\xed\xb3\x80", FALSE, 0x0 },
		{ "\xed\xb4\x80", FALSE, 0x0 },
		{ "\xed\xb5\x80", FALSE, 0x0 },
		{ "\xed\xb6\x80", FALSE, 0x0 },
		{ "\xed\xb7\x80", FALSE, 0x0 },
		{ "\xed\xb8\x80", FALSE, 0x0 },
		{ "\xed\xb9\x80", FALSE, 0x0 },
		{ "\xed\xba\x80", FALSE, 0x0 },
		{ "\xed\xbb\x80", FALSE, 0x0 },
		{ "\xed\xbc\x80", FALSE, 0x0 },
		{ "\xed\xbd\x80", FALSE, 0x0 },
		{ "\xed\xbf\x80", FALSE, 0x0 }, /* .. U+DFFF */
		{ "\xe2\x82\xa1", TRUE, 0x20A1 },  /* U+20A1 */
		{ "\xe2\x28\xa1", FALSE, 0x0 }, /* invalid 2nd octet */
		{ "\xe2\x82\x28", FALSE, 0x0 }, /* invalid 3rd octet */
		{ "\xf0\x90\x8c\xbc", TRUE, 0x1033C },  /* U+1033C */
		{ "\xf0\x28\x8c\xbc", FALSE, 0x0 }, /*invalid 2nd octet*/
		{ "\xf0\x90\x28\xbc", FALSE, 0x0 }, /* invalid 3rd octet */
		{ "\xf0\x28\x8c\x28", FALSE, 0x0 }, /* invalid 4th octet */
		{ "\xf4\x80\x80\x80", TRUE, 0x100000 }, /* U+100000, supplementary plane start */
		{ "\xf4\x8f\xbf\xbf", TRUE, 0x10FFFF }, /* U+10FFFF, maximum value */
		{ "\xf8\xa1\xa1\xa1\xa1", FALSE, 0x0 }, /* invalid unicode */
		{ "\xfc\xa1\xa1\xa1\xa1\xa1", FALSE, 0x0 }, /* invalid unicode */
	};

	test_begin("unichar valid unicode");

	for(size_t i = 0; i < N_ELEMENTS(test_cases); i++) {
		unichar_t chr;
		if (test_cases[i].valid) {
			test_assert_idx(uni_utf8_get_char(test_cases[i].input, &chr) > 0, i);
			test_assert_idx(test_cases[i].expected == chr, i);
		} else {
			test_assert_idx(uni_utf8_get_char(test_cases[i].input, &chr) < 1, i);
		}
	}

	test_end();
}

static void test_unichar_surrogates(void)
{
	unichar_t orig, high, low;
	test_begin("unichar surrogates");

	orig = 0x10437;
	uni_split_surrogate(orig, &high, &low);
	test_assert(high == 0xD801);
	test_assert(low == 0xDC37);
	test_assert(uni_join_surrogate(high, low) == orig);

	test_end();
}

static void test_unichar_collation(void)
{
	const char *in[] = {
		/* Plain ASCII letters will be upper-cased */
		"Plain!",
		/* U+00FC " " U+00B3 */
		"\xc3\xbc \xc2\xb3",
		/* U+01C4 "enan" */
		"\xC7\x84\x65\x6E\x61\x6E",
		/* Bad characters will be substituted with replacement character */
		"Bad \xFF Characters",
		/* "c" U+00F4 "t" U+00E9 */
		"c\xC3\xB4t\xC3\xA9",
	};
	const char *exp[] = {
		/* Plain ASCII letters are upper-cased */
		"PLAIN!",
		/* "U" U+0308 " 3" */
		"U\xcc\x88 3",
		/* "Dz" U+030C "ENAN" */
		"\x44\x7A\xCC\x8C\x45\x4E\x41\x4E",
		/* Bad characters are substituted with replacement character */
		"BAD \xEF\xBF\xBD CHARACTERS",
		/* "CO" U+0302 "TE" U+0301 */
		"CO\xCC\x82TE\xCC\x81",
	};

	unsigned int n_in = N_ELEMENTS(in), n_exp = N_ELEMENTS(exp), i;
	buffer_t *collate_out;

	i_assert(n_in == n_exp);

	test_begin("unichar collation");

	collate_out = buffer_create_dynamic(default_pool, 32);

	for (i = 0; i < n_in; i++) {
		buffer_set_used_size(collate_out, 0);
		uni_utf8_to_decomposed_titlecase(in[i], strlen(in[i]),
						 collate_out);
		test_assert_strcmp_idx(str_c(collate_out), exp[i], i);
	}

	buffer_free(&collate_out);
	test_end();
}

static void test_unichar_grapheme_clusters(void)
{
	const char *in[] = {
		/* Simple ASCII */
		"frop",
		/* U+1019 U+1039 U+1018 U+102C U+1037 */
		"\xE1\x80\x99\xE1\x80\xB9\xE1\x80\x98\xE1\x80\xAC\xE1\x80\xB7"
	};
	/* Use TAB to mark grapheme boundaries */
	const char *tb[] = {
		/* Simple ASCII: break points after every byte */
		"f\tr\to\tp\t",
		/* U+1019 U+1039 U+1018 U+102C U+1037 */
		"\xE1\x80\x99\xE1\x80\xB9\xE1\x80\x98\t\xE1\x80\xAC\xE1\x80\xB7\t",
	};
	unsigned int n_in = N_ELEMENTS(in), n_tb = N_ELEMENTS(tb), i;

	i_assert(n_in == n_tb);

	test_begin("unichar grapheme clusters");

	string_t *tb_buf = t_str_new(256);
	for (i = 0; i < n_in; i++) {
		struct uni_gc_scanner gcsc;

		str_truncate(tb_buf, 0);
		uni_gc_scanner_init(&gcsc, in[i], strlen(in[i]));

		while (!uni_gc_scan_at_end(&gcsc)) {
			const unsigned char *gc;
			size_t gc_size;

			gc = uni_gc_scan_get(&gcsc, &gc_size);
			if (gc_size == 0)
				break;

			str_append_data(tb_buf, gc, gc_size);
			str_append_c(tb_buf, '\t');
			uni_gc_scan_shift(&gcsc);
		}

		test_assert_strcmp_idx(str_c(tb_buf), tb[i], i);
	}
	test_end();
}

void test_unichar(void)
{
	static const char overlong_utf8[] = "\xf8\x80\x95\x81\xa1";
	unichar_t chr, chr2;
	string_t *str = t_str_new(16);

	test_begin("unichars encode/decode");
	for (chr = 0; chr <= 0x10ffff; chr++) {
		/* skip surrogates */
		if ((chr & 0xfff800) == 0xd800)
			continue;
		/* The bottom 6 bits should be irrelevant to code coverage,
		   only test 000000, 111111, and something in between. */
		if ((chr & 63) == 1)
			chr += i_rand_limit(62); /* After 0, somewhere between 1 and 62 */
		else if ((chr & 63) > 0 && (chr & 63) < 63)
			chr |= 63; /* After random, straight to 63 */

		str_truncate(str, 0);
		uni_ucs4_to_utf8_c(chr, str);
		test_assert(uni_utf8_str_is_valid(str_c(str)));
		test_assert(uni_utf8_get_char(str_c(str), &chr2) == (int)uni_utf8_char_bytes(*str_data(str)));
		test_assert(chr2 == chr);

		if ((chr & 0x63) == 0) {
			unsigned int utf8len = uni_utf8_char_bytes((unsigned char)*str_c(str));

			/* virtually truncate the byte string */
			while (--utf8len > 0)
				test_assert(uni_utf8_get_char_n(str_c(str), utf8len, &chr2) == 0);

			utf8len = uni_utf8_char_bytes((unsigned char)*str_c(str));

			/* actually truncate the byte stream */
			while (--utf8len > 0) {
				str_truncate(str, utf8len);
				test_assert(!uni_utf8_str_is_valid(str_c(str)));
				test_assert(uni_utf8_get_char(str_c(str), &chr2) == 0);
			}
		}
	}
	test_end();

	test_unichar_collation();

	test_begin("unichar overlong");
	test_assert(!uni_utf8_str_is_valid(overlong_utf8));
	test_assert(uni_utf8_get_char(overlong_utf8, &chr2) < 0);
	test_end();

	test_unichar_uni_utf8_strlen();
	test_unichar_uni_utf8_partial_strlen_n();
	test_unichar_valid_unicode();
	test_unichar_surrogates();

	test_unichar_grapheme_clusters();
}
